import { env } from "../config/env.js";
import { alerts, appSettings, channels, deliveries, incidents, monitors, results, subscriptions, tenants } from "../storage/repositories.js";
import { dispatchAlerts, dispatchStatusSubscriptions } from "../notifications/service.js";
import { discoverMonitors } from "../checks/discovery.js";
import { backupDir, createAutoBackup, createBackup, newestAutoBackupAt } from "../backup/backupService.js";
import { runMonitorCheck } from "../checks/monitorRunner.js";
import { logFailure } from "../utils/failures.js";

let running = false;
let lastRetentionRun = 0;

/* Every SCHEDULER_INTERVAL_SECONDS the scheduler checks the monitors that are
   due, removes old results, runs scheduled discovery and the organizations'
   backups, and writes the automatic backup. Each step, and each monitor and
   organization within a step, fails on its own: the failure goes to the server
   log with a reference and the next step to take, the remaining work goes on,
   and the failed work is tried again at the next run. */
export const startScheduler = (intervalSeconds = env.schedulerIntervalSeconds) => {
  void runScheduledWork();
  const timer = setInterval(runScheduledWork, intervalSeconds * 1000);
  timer.unref();
  return () => clearInterval(timer);
};

/** One run of the scheduler; a run that starts while the previous one is still busy does nothing. */
export const runScheduledWork = async () => {
  if (running) return;
  running = true;
  try {
    await attempt("Selecting the monitors that are due", databaseHint, runDueChecks);
    await attempt("Removing old check results and alerts", databaseHint, runRetentionIfDue);
    await attempt("Scheduled discovery", databaseHint, runDiscoveryIfDue);
    await attempt("Scheduled backups", databaseHint, runBackupIfDue);
    await attempt("The automatic backup", backupHint(), runAutoBackupIfDue);
  } finally {
    running = false;
  }
};

const databaseHint = "Check that the database file is readable and writable and that its disk has free space.";
const backupHint = () => `Check that ${backupDir} is writable and has free space.`;

const attempt = async (work: string, nextStep: string, run: () => unknown) => {
  try {
    await run();
  } catch (error) {
    logFailure(`${work} failed`, error, `${nextStep} crt.watch keeps running and tries again at the next scheduler run.`);
  }
};

const runDueChecks = async () => {
  const due = monitors.due(env.checkConcurrency);
  await Promise.allSettled(due.map(runMonitor));
};

const runDiscoveryIfDue = async () => {
  for (const tenant of tenants.list()) {
    await attempt(`Scheduled discovery for organization ${tenant.slug}`, "Check the discovery domains of the organization in Operations.", async () => {
      const settings = appSettings.discovery(tenant.id);
      if (!settings.enabled || !settings.domains.length || !elapsed(settings.lastRunAt, settings.intervalHours)) return;
      const suggestions = (await Promise.all(settings.domains.map(discoverMonitors))).flat();
      appSettings.set("discovery", { ...settings, suggestions, lastRunAt: new Date().toISOString() }, tenant.id);
    });
  }
};

const runBackupIfDue = async () => {
  for (const tenant of tenants.list()) {
    await attempt(`The scheduled backup of organization ${tenant.slug}`, backupHint(), () => {
      const settings = appSettings.backups(tenant.id);
      if (!settings.enabled || !elapsed(settings.lastRunAt, settings.intervalHours)) return;
      createBackup(settings);
      appSettings.set("backups", { ...settings, lastRunAt: new Date().toISOString() }, tenant.id);
    });
  }
};

// Always-on safety net: unlike the tenant-configured backups above, this
// schedule lives in env config and the backup directory itself, so it keeps
// working even when the database (and the settings stored in it) is lost.
const runAutoBackupIfDue = () => {
  if (!env.autoBackupEnabled || env.autoBackupIntervalHours <= 0) return;
  if (elapsed(newestAutoBackupAt(), env.autoBackupIntervalHours)) createAutoBackup(env.autoBackupKeep);
};

const elapsed = (lastRunAt: string | null | undefined, intervalHours: number) =>
  !lastRunAt || Date.now() - new Date(lastRunAt).getTime() >= intervalHours * 3_600_000;

const runRetentionIfDue = () => {
  if (Date.now() - lastRetentionRun < 3_600_000) return;
  lastRetentionRun = Date.now();
  const retention = appSettings.retention();
  results.prune(retention.checkResultsDays);
  alerts.prune(retention.alertHistoryDays);
  deliveries.prune(retention.alertHistoryDays);
};

const runMonitor = async (monitor: ReturnType<typeof monitors.list>[number]) => {
  try {
    const previous = results.list(monitor.id, 1)[0];
    const result = await runMonitorCheck(monitor, previous);
    const openIncident = incidents.openForMonitor(monitor.id);
    results.insert(result);
    const statusEvent = result.status === "OK" ? (openIncident ? "resolved" : null) : (!openIncident ? "opened" : null);
    incidents.sync(monitor, result);
    monitors.markChecked(monitor, result);
    await dispatchAlerts(monitor, result, channels.list(monitor.tenantId));
    if (statusEvent) await dispatchStatusSubscriptions(monitor, result, statusEvent, subscriptions.list(monitor.tenantId));
  } catch (error) {
    logFailure(`Checking monitor ${monitor.id} of organization ${monitor.tenantId} failed`, error, "The other monitors are checked as usual; the error below names the cause.");
  }
};

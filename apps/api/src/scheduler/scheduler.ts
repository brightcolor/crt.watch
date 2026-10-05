import { env } from "../config/env.js";
import { alerts, appSettings, channels, deliveries, incidents, monitors, results, subscriptions, tenants } from "../storage/repositories.js";
import { dispatchAlerts, dispatchStatusSubscriptions } from "../notifications/service.js";
import { discoverMonitors } from "../checks/discovery.js";
import { createAutoBackup, createBackup, newestAutoBackupAt } from "../backup/backupService.js";
import { runMonitorCheck } from "../checks/monitorRunner.js";

let running = false;
let lastRetentionRun = 0;

export const startScheduler = () => {
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const due = monitors.due(env.checkConcurrency);
      await Promise.allSettled(due.map(runMonitor));
      runRetentionIfDue();
      await runDiscoveryIfDue();
      runBackupIfDue();
      runAutoBackupIfDue();
    } finally {
      running = false;
    }
  };
  void tick();
  setInterval(tick, 30_000).unref();
};

const runDiscoveryIfDue = async () => {
  for (const tenant of tenants.list()) {
    const settings = appSettings.discovery(tenant.id);
    if (!settings.enabled || !settings.domains.length || !elapsed(settings.lastRunAt, settings.intervalHours)) continue;
    const suggestions = (await Promise.all(settings.domains.map(discoverMonitors))).flat();
    appSettings.set("discovery", { ...settings, suggestions, lastRunAt: new Date().toISOString() }, tenant.id);
  }
};

const runBackupIfDue = () => {
  for (const tenant of tenants.list()) {
    const settings = appSettings.backups(tenant.id);
    if (!settings.enabled || !elapsed(settings.lastRunAt, settings.intervalHours)) continue;
    createBackup(settings);
    appSettings.set("backups", { ...settings, lastRunAt: new Date().toISOString() }, tenant.id);
  }
};

// Always-on safety net: unlike the tenant-configured backups above, this
// schedule lives in env config and the backup directory itself, so it keeps
// working even when the database (and the settings stored in it) is lost.
const runAutoBackupIfDue = () => {
  if (!env.autoBackupEnabled || env.autoBackupIntervalHours <= 0) return;
  try {
    if (elapsed(newestAutoBackupAt(), env.autoBackupIntervalHours)) createAutoBackup(env.autoBackupKeep);
  } catch (error) {
    console.error("Automatic backup failed:", error instanceof Error ? error.message : error);
  }
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
    console.error("Check failed for monitor %s:", monitor.id, error instanceof Error ? error.message : error);
  }
};

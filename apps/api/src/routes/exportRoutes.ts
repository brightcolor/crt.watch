import { Router } from "express";
import { requireTenantRole } from "../auth/auth.js";
import { appSettings, channels, monitors, results } from "../storage/repositories.js";
import { statusPageConflict, statusPagesSchema } from "../status/publication.js";
import { monitorQuota, monitorsBeyondLimit } from "./monitorQuota.js";
import { defaultsFor, monitorInputSchema } from "./monitorSchemas.js";
import type { ChannelType, Monitor, NotificationChannel, StatusPageSettings } from "../types.js";
import { id } from "../utils/id.js";
import { nowIso } from "../utils/time.js";
import { redactConfigSecrets } from "../utils/secrets.js";

export const exportRoutes = Router();

exportRoutes.get("/monitors.json", (req, res) => {
  res.attachment("crtwatch-monitors.json").json({ monitors: monitors.list(req.currentTenant!.id).map(publicMonitor) });
});

// Importing creates monitors, so it needs the role that creates them one by one,
// and the file's monitors are checked against the monitor limit before the first one is created.
exportRoutes.post("/monitors.json", requireTenantRole("owner", "admin", "member"), (req, res) => {
  const imported = validMonitors(req.body?.monitors);
  const quota = monitorQuota(req.currentTenant!.id);
  if (imported.length > quota.left) return res.status(402).json({ error: monitorsBeyondLimit(imported.length, quota, "import") });
  const created = imported.map((monitor) => publicMonitor(monitors.create({ ...monitor, tenantId: req.currentTenant!.id })));
  res.status(201).json({ imported: created.length, monitors: created });
});

exportRoutes.get("/backup.json", (_req, res) => {
  res.attachment("crtwatch-backup.json").json({
    version: 1,
    exportedAt: new Date().toISOString(),
    monitors: monitors.list(_req.currentTenant!.id).map(publicMonitor),
    notificationChannels: channels.list(_req.currentTenant!.id).map((channel) => ({ ...channel, config: redactConfigSecrets(channel.config ?? {}) })),
    notificationRoutes: appSettings.notificationRoutes(_req.currentTenant!.id),
    settings: {
      alerting: appSettings.alerting(_req.currentTenant!.id),
      smtp: redactConfigSecrets(appSettings.smtp(_req.currentTenant!.id) as unknown as Record<string, unknown>),
      retention: appSettings.retention(_req.currentTenant!.id),
      ctWatch: appSettings.ctWatch(_req.currentTenant!.id),
      maintenance: appSettings.maintenance(_req.currentTenant!.id),
      tlsPolicy: appSettings.tlsPolicy(_req.currentTenant!.id),
      sslLabs: appSettings.sslLabs(_req.currentTenant!.id),
      statusPages: appSettings.statusPages(_req.currentTenant!.id),
      discovery: { ...appSettings.discovery(_req.currentTenant!.id), suggestions: [] },
      backups: appSettings.backups(_req.currentTenant!.id)
    }
  });
});

// A restore writes settings, channels and status pages, so it needs the role that manages them.
exportRoutes.post("/restore", requireTenantRole("owner", "admin"), (req, res) => {
  const tenantId = req.currentTenant!.id;
  const input = req.body ?? {};

  // Status pages publish monitors under public addresses, so they are checked before anything is written.
  let statusPages: StatusPageSettings | undefined;
  if (input.settings?.statusPages) {
    const parsed = statusPagesSchema.safeParse(input.settings.statusPages);
    if (!parsed.success) return res.status(400).json({ error: `The status pages in this backup cannot be restored: ${parsed.error.issues[0]?.message ?? "a page is incomplete"}. Correct them in the file or remove settings.statusPages, then restore again.` });
    const conflict = statusPageConflict(tenantId, parsed.data.pages);
    if (conflict) return res.status(409).json({ error: `The status pages in this backup cannot be restored. ${conflict} Change it in the file or remove settings.statusPages, then restore again.` });
    statusPages = parsed.data;
  }

  // The backup's monitors count against the monitor limit, so they are checked before anything is written as well.
  const restoredMonitors = validMonitors(input.monitors);
  const quota = monitorQuota(tenantId);
  if (restoredMonitors.length > quota.left) return res.status(402).json({ error: monitorsBeyondLimit(restoredMonitors.length, quota, "backup") });

  // Channels keep their ids, so restored monitors and routes still point at them.
  // An id that belongs to a channel of another organization gets a new one, and
  // the references in this backup follow it; the other channel stays untouched.
  const renamed = new Map<string, string>();
  let restoredChannels = 0;
  for (const item of Array.isArray(input.notificationChannels) ? input.notificationChannels : []) {
    const channel = restoreChannel(item);
    if (!channel) continue;
    if (channels.get(channel.id) && !channels.get(channel.id, tenantId)) {
      renamed.set(channel.id, id());
      channel.id = renamed.get(channel.id)!;
    }
    if (channels.upsert({ ...channel, tenantId })) restoredChannels += 1;
  }

  const created = restoredMonitors.map((monitor) => publicMonitor(monitors.create({
    ...monitor,
    notificationChannelIds: renameIds(monitor.notificationChannelIds, renamed),
    notificationRecipients: renameKeys(monitor.notificationRecipients, renamed),
    tenantId
  })));
  if (input.settings?.alerting) appSettings.set("alerting", input.settings.alerting, tenantId);
  if (input.settings?.retention) appSettings.set("retention", input.settings.retention, tenantId);
  if (input.settings?.ctWatch) appSettings.set("ctWatch", input.settings.ctWatch, tenantId);
  if (input.settings?.maintenance) appSettings.set("maintenance", input.settings.maintenance, tenantId);
  if (input.settings?.tlsPolicy) appSettings.set("tlsPolicy", input.settings.tlsPolicy, tenantId);
  if (input.settings?.sslLabs) appSettings.set("sslLabs", input.settings.sslLabs, tenantId);
  if (statusPages) appSettings.set("statusPages", statusPages, tenantId);
  if (input.settings?.discovery) appSettings.set("discovery", input.settings.discovery, tenantId);
  if (input.settings?.backups) appSettings.set("backups", input.settings.backups, tenantId);
  if (Array.isArray(input.notificationRoutes)) {
    appSettings.set("notificationRoutes", input.notificationRoutes.map((route: any) => route && typeof route === "object"
      ? { ...route, channelIds: renameIds(route.channelIds, renamed), recipients: renameKeys(route.recipients, renamed) }
      : route), tenantId);
  }
  res.status(201).json({ imported: created.length, restoredChannels, monitors: created });
});

/** The entries of an import or a backup that are valid monitors; the other entries are left out. */
const validMonitors = (input: unknown) => (Array.isArray(input) ? input : []).flatMap((item) => {
  const parsed = monitorInputSchema.safeParse(defaultsFor(item));
  return parsed.success ? [parsed.data] : [];
});

const renameIds = <T>(ids: T, renamed: Map<string, string>): T =>
  (Array.isArray(ids) ? ids.map((value) => (typeof value === "string" ? renamed.get(value) ?? value : value)) : ids) as T;

const renameKeys = <T>(record: T, renamed: Map<string, string>): T =>
  (record && typeof record === "object" && !Array.isArray(record)
    ? Object.fromEntries(Object.entries(record).map(([key, value]) => [renamed.get(key) ?? key, value]))
    : record) as T;

exportRoutes.get("/certificates.csv", (_req, res) => {
  const latest = results.latestByMonitor(_req.currentTenant!.id);
  const rows = [["name", "host", "port", "status", "days_remaining", "valid_until", "issuer", "fingerprint_sha256", "tls_grade", "ssl_labs_grade", "resolved_addresses"]];
  for (const monitor of monitors.list(_req.currentTenant!.id)) {
    const result = latest[monitor.id];
    rows.push([monitor.name, monitor.host, String(monitor.port), monitor.lastStatus, String(result?.daysRemaining ?? ""), result?.validUntil ?? "", result?.issuer ?? "", result?.fingerprintSha256 ?? "", result?.tlsGrade ?? "", result?.sslLabsGrade ?? "", result?.dns?.addresses.join(" ") ?? ""]);
  }
  res.type("text/csv").attachment("crtwatch-certificates.csv").send(toCsv(rows));
});

exportRoutes.get("/history.csv", (_req, res) => {
  const rows = [["monitor_id", "checked_at", "status", "message", "days_remaining", "valid_until", "issuer", "tls_grade", "ssl_labs_grade"]];
  for (const monitor of monitors.list(_req.currentTenant!.id)) {
    for (const result of results.list(monitor.id, 1000)) {
      rows.push([monitor.id, result.checkedAt, result.status, result.message, String(result.daysRemaining ?? ""), result.validUntil ?? "", result.issuer ?? "", result.tlsGrade ?? "", result.sslLabsGrade ?? ""]);
    }
  }
  res.type("text/csv").attachment("crtwatch-history.csv").send(toCsv(rows));
});

const toCsv = (rows: string[][]) => rows.map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(",")).join("\n");

const publicMonitor = (monitor: Monitor) => ({ ...monitor, config: redactConfigSecrets(monitor.config ?? {}) });

const channelTypes: ChannelType[] = ["email", "pushover", "webhook", "discord", "slack", "telegram", "gotify", "ntfy", "teams", "mattermost", "matrix", "pagerduty", "opsgenie"];

const restoreChannel = (item: any): Omit<NotificationChannel, "tenantId"> | null => {
  if (!item?.name || !channelTypes.includes(item.type)) return null;
  const now = nowIso();
  return {
    id: typeof item.id === "string" ? item.id : id(),
    name: String(item.name).slice(0, 100),
    type: item.type,
    enabled: Boolean(item.enabled),
    config: item.config && typeof item.config === "object" ? item.config : {},
    createdAt: typeof item.createdAt === "string" ? item.createdAt : now,
    updatedAt: now
  };
};

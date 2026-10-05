import { Router } from "express";
import { channels, incidents, monitors, results, subscriptions } from "../storage/repositories.js";
import { monitorInputSchema } from "./monitorSchemas.js";
import { monitorLimitReached, monitorQuota } from "./monitorQuota.js";
import { dispatchAlerts, dispatchStatusSubscriptions } from "../notifications/service.js";
import type { Monitor } from "../types.js";
import { redactConfigSecrets } from "../utils/secrets.js";
import { runMonitorCheck } from "../checks/monitorRunner.js";
import { requireTenantRole } from "../auth/auth.js";

export const monitorRoutes = Router();

monitorRoutes.get("/", (req, res) => {
  const latest = results.latestByMonitor(req.currentTenant!.id);
  res.json(monitors.list(req.currentTenant!.id).map((monitor) => ({ ...publicMonitor(monitor), latestResult: latest[monitor.id] ?? null })));
});

monitorRoutes.post("/", requireTenantRole("owner", "admin", "member"), async (req, res) => {
  const parsed = monitorInputSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid monitor." });
  const quota = monitorQuota(req.currentTenant!.id);
  if (quota.left < 1) return res.status(402).json({ error: monitorLimitReached(quota) });
  const monitor = monitors.create({ ...parsed.data, tenantId: req.currentTenant!.id });
  res.status(201).json(publicMonitor(monitor));
});

monitorRoutes.post("/:id/clone", requireTenantRole("owner", "admin", "member"), (req, res) => {
  const source = monitors.get(req.params.id, req.currentTenant!.id);
  if (!source) return res.status(404).json({ error: "Monitor not found." });
  const quota = monitorQuota(req.currentTenant!.id);
  if (quota.left < 1) return res.status(402).json({ error: monitorLimitReached(quota) });
  const monitor = monitors.create(cloneMonitor(source, req.currentTenant!.id));
  res.status(201).json(publicMonitor(monitor));
});

monitorRoutes.post("/bulk", requireTenantRole("owner", "admin", "member"), (req, res) => {
  const lines = String(req.body?.text ?? "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const quota = monitorQuota(req.currentTenant!.id);
  const created = [];
  const errors = [];
  for (const line of lines) {
    const parsedLine = parseBulkLine(line);
    const parsed = monitorInputSchema.safeParse(parsedLine);
    if (parsed.success && created.length < quota.left) created.push(publicMonitor(monitors.create({ ...parsed.data, tenantId: req.currentTenant!.id })));
    else if (parsed.success) errors.push({ line, error: monitorLimitReached(quota) });
    else errors.push({ line, error: parsed.error.issues[0]?.message ?? "Invalid monitor." });
  }
  res.status(errors.length ? 207 : 201).json({ imported: created.length, errors, monitors: created });
});

monitorRoutes.get("/:id", (req, res) => {
  const monitor = monitors.get(req.params.id, req.currentTenant!.id);
  if (!monitor) return res.status(404).json({ error: "Monitor not found." });
  res.json({ ...publicMonitor(monitor), latestResult: results.list(monitor.id, 1)[0] ?? null });
});

const parseBulkLine = (line: string) => {
  const [target, ...options] = line.split(/\s+/);
  const optionMap = Object.fromEntries(options.map((option) => {
    const [key, value = ""] = option.split("=");
    return [key.toLowerCase(), value.toLowerCase()];
  }));
  const starttls = optionMap.starttls;
  const type = optionMap.type || (starttls ? `${starttls}_starttls` : "https");
  const portByType: Record<string, number> = { https: 443, tls: 443, smtps: 465, imaps: 993, pop3s: 995, ldaps: 636, ftps: 990, xmpps: 5223, smtp_starttls: 587, imap_starttls: 143, pop3_starttls: 110, ftp_starttls: 21, http: 80, tcp: 80, dns: 53, http_login: 443, ssh: 22, ftp: 21, smtp: 25, imap: 143, pop3: 110 };
  const [host, rawPort] = target.replace(/^https?:\/\//, "").split(/[/:]/);
  const port = Number(optionMap.port || rawPort || portByType[type] || 443);
  return {
    name: optionMap.name || host,
    host,
    port,
    type,
    enabled: true,
    intervalSeconds: 3600,
    timeoutSeconds: 10,
    warningDays: 30,
    criticalDays: 7,
    sniEnabled: true,
    sniHost: null,
    validateCertificate: true,
    allowSelfSigned: false,
    tags: optionMap.tags ? optionMap.tags.split(",").filter(Boolean) : [],
    notes: null,
    owner: null,
    notificationChannelIds: [],
    notificationRecipients: {},
    config: optionMap.security || optionMap.securitymode ? { securityMode: optionMap.security || optionMap.securitymode } : {},
    maintenanceWindows: null
  };
};

monitorRoutes.put("/:id", requireTenantRole("owner", "admin", "member"), (req, res) => {
  const monitor = monitors.get(req.params.id, req.currentTenant!.id);
  if (!monitor) return res.status(404).json({ error: "Monitor not found." });
  const parsed = monitorInputSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid monitor." });
  res.json(publicMonitor(monitors.update({ ...monitor, ...parsed.data, config: mergeMaskedSecrets(monitor.config, parsed.data.config) })));
});

monitorRoutes.delete("/:id", requireTenantRole("owner", "admin"), (req, res) => {
  monitors.delete(req.params.id, req.currentTenant!.id);
  res.status(204).end();
});

monitorRoutes.post("/:id/check", requireTenantRole("owner", "admin", "member"), async (req, res) => {
  const monitor = monitors.get(req.params.id, req.currentTenant!.id);
  if (!monitor) return res.status(404).json({ error: "Monitor not found." });
  if (!monitor.enabled) return res.status(409).json({ error: "Monitor is paused." });
  const previous = results.list(monitor.id, 1)[0];
  const result = await runMonitorCheck(monitor, previous);
  const openIncident = incidents.openForMonitor(monitor.id);
  results.insert(result);
  const statusEvent = result.status === "OK" ? (openIncident ? "resolved" : null) : (!openIncident ? "opened" : null);
  incidents.sync(monitor, result);
  monitors.markChecked(monitor, result);
  await dispatchAlerts(monitor, result, channels.list(monitor.tenantId));
  if (statusEvent) await dispatchStatusSubscriptions(monitor, result, statusEvent, subscriptions.list(monitor.tenantId));
  res.json(result);
});

monitorRoutes.get("/:id/results", (req, res) => {
  if (!monitors.get(req.params.id, req.currentTenant!.id)) return res.status(404).json({ error: "Monitor not found." });
  res.json(results.list(req.params.id, Number(req.query.limit ?? 100)));
});

monitorRoutes.get("/:id/incidents", (req, res) => {
  if (!monitors.get(req.params.id, req.currentTenant!.id)) return res.status(404).json({ error: "Monitor not found." });
  res.json(incidents.listForMonitor(req.params.id, Number(req.query.limit ?? 50)));
});

const publicMonitor = (monitor: Monitor) => ({ ...monitor, config: redactConfigSecrets(monitor.config ?? {}) });

const cloneMonitor = (monitor: Monitor, tenantId: string): Omit<Monitor, "id" | "lastStatus" | "createdAt" | "updatedAt" | "nextCheckAt"> => ({
  tenantId,
  name: `${monitor.name.slice(0, 113)} copy`,
  host: monitor.host,
  port: monitor.port,
  type: monitor.type,
  enabled: false,
  intervalSeconds: monitor.intervalSeconds,
  timeoutSeconds: monitor.timeoutSeconds,
  warningDays: monitor.warningDays,
  criticalDays: monitor.criticalDays,
  gracePeriodSeconds: monitor.gracePeriodSeconds,
  sniEnabled: monitor.sniEnabled,
  sniHost: monitor.sniHost,
  validateCertificate: monitor.validateCertificate,
  allowSelfSigned: monitor.allowSelfSigned,
  tags: monitor.tags,
  notes: monitor.notes,
  owner: monitor.owner,
  notificationChannelIds: monitor.notificationChannelIds,
  notificationRecipients: monitor.notificationRecipients,
  config: monitor.config,
  maintenanceWindows: monitor.maintenanceWindows
});

const mergeMaskedSecrets = (previous: Record<string, unknown>, next: Record<string, unknown>) =>
  Object.fromEntries(Object.entries(next ?? {}).map(([key, value]) => [
    key,
    value === "********" ? previous?.[key] : value
  ]));

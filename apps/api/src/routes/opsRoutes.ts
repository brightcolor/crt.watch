import { Router } from "express";
import { z } from "zod";
import { createBackup, deleteBackup, findBackupPath, listBackups } from "../backup/backupService.js";
import { createPlainApiToken, hashToken, requireAdmin, requireTenantRole } from "../auth/auth.js";
import { discoverMonitors } from "../checks/discovery.js";
import { buildManualSslLabsResult, normalizeSslLabsHost, runManualSslLabsAssessment } from "../checks/sslLabsManual.js";
import { apiTokens, appSettings, auditLogs, deliveries, incidents, monitors, results, tenants, users } from "../storage/repositories.js";
import { statusPageConflict, statusPagesSchema } from "../status/publication.js";
import { id } from "../utils/id.js";
import { monitorInputSchema, monitorTypes } from "./monitorSchemas.js";
import type { DiscoveredMonitor, Monitor } from "../types.js";

export const opsRoutes = Router();

opsRoutes.get("/settings/maintenance", (req, res) => res.json(appSettings.maintenance(req.currentTenant!.id)));
opsRoutes.put("/settings/maintenance", requireTenantRole("owner", "admin"), (req, res) => saveSetting(req, res, "maintenance", maintenanceSchema));
opsRoutes.get("/settings/tls-policy", (req, res) => res.json(appSettings.tlsPolicy(req.currentTenant!.id)));
opsRoutes.put("/settings/tls-policy", requireTenantRole("owner", "admin"), (req, res) => saveSetting(req, res, "tlsPolicy", tlsPolicySchema));
opsRoutes.get("/settings/ssl-labs", (req, res) => res.json(appSettings.sslLabs(req.currentTenant!.id)));
opsRoutes.put("/settings/ssl-labs", requireTenantRole("owner", "admin"), (req, res) => saveSetting(req, res, "sslLabs", sslLabsSchema));
opsRoutes.post("/ssl-labs/register", requireTenantRole("owner", "admin"), async (req, res) => {
  const parsed = sslLabsRegistrationSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid SSL Labs registration." });
  try {
    const providerResponse = await registerWithSslLabs(parsed.data);
    const current = appSettings.sslLabs(req.currentTenant!.id);
    const next = { ...current, registeredEmail: parsed.data.email };
    appSettings.set("sslLabs", next, req.currentTenant!.id);
    res.status(201).json({ ok: true, settings: next, providerResponse });
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "SSL Labs registration failed." });
  }
});
opsRoutes.post("/ssl-labs/trigger", requireTenantRole("owner", "admin", "member"), async (req, res) => {
  const parsed = sslLabsTriggerSchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid SSL Labs trigger." });
  if (!parsed.data.monitorId && req.tenantRole === "member") return res.status(403).json({ error: "Organization admin permission required for arbitrary hosts." });
  const monitor = parsed.data.monitorId ? monitors.get(parsed.data.monitorId, req.currentTenant!.id) : null;
  if (parsed.data.monitorId && !monitor) return res.status(404).json({ error: "Monitor not found." });
  const settings = appSettings.sslLabs(req.currentTenant!.id);
  if (!settings.registeredEmail) return res.status(409).json({ error: "Configure a registered SSL Labs email before triggering assessments." });
  try {
    const host = normalizeSslLabsHost(monitor?.host ?? parsed.data.host ?? "");
    const assessment = await runManualSslLabsAssessment(host, monitor ?? undefined, settings, parsed.data.startNewScan);
    if (!monitor) return res.json({ host, assessment });
    const previous = results.list(monitor.id, 1)[0];
    const stored = buildManualSslLabsResult(monitor, previous, assessment);
    results.insert(stored);
    res.json({ host, assessment: stored });
  } catch (error) {
    const message = error instanceof Error ? error.message : "SSL Labs trigger failed.";
    const status = message.includes("valid public hostname") ? 400 : message.includes("not supported") ? 409 : 502;
    res.status(status).json({ error: message });
  }
});
opsRoutes.get("/settings/status-pages", (req, res) => res.json(appSettings.statusPages(req.currentTenant!.id)));
// A status page publishes monitors, and its slug is a public address that no other organization may hold.
opsRoutes.put("/settings/status-pages", requireTenantRole("owner", "admin"), (req, res) => {
  const parsed = statusPagesSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid status pages. Check slug, title and labels of each page." });
  const conflict = statusPageConflict(req.currentTenant!.id, parsed.data.pages);
  if (conflict) return res.status(409).json({ error: conflict });
  appSettings.set("statusPages", parsed.data, req.currentTenant!.id);
  res.json(parsed.data);
});
opsRoutes.get("/settings/discovery", (req, res) => res.json(appSettings.discovery(req.currentTenant!.id)));
opsRoutes.put("/settings/discovery", requireTenantRole("owner", "admin"), (req, res) => saveSetting(req, res, "discovery", discoverySchema));
opsRoutes.get("/settings/backups", (req, res) => res.json(appSettings.backups(req.currentTenant!.id)));
opsRoutes.put("/settings/backups", requireTenantRole("owner", "admin"), (req, res) => saveSetting(req, res, "backups", backupsSchema));

opsRoutes.post("/discovery/run", requireTenantRole("owner", "admin"), async (_req, res) => {
  const settings = appSettings.discovery(_req.currentTenant!.id);
  const suggestions = (await Promise.all(settings.domains.map(discoverMonitors))).flat();
  const next = { ...settings, suggestions, lastRunAt: new Date().toISOString() };
  appSettings.set("discovery", next, _req.currentTenant!.id);
  res.json(next);
});

opsRoutes.post("/discovery/import", requireTenantRole("owner", "admin", "member"), (req, res) => {
  const parsed = z.object({ monitors: z.array(discoveredMonitorSchema).optional() }).safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid discovery import." });
  const settings = appSettings.discovery(req.currentTenant!.id);
  const requested = parsed.data.monitors?.length ? parsed.data.monitors : settings.suggestions;
  const existing = new Set(monitors.list(req.currentTenant!.id).map(monitorKey));
  const created: Monitor[] = [];
  const skipped: DiscoveredMonitor[] = [];
  const errors: Array<{ monitor: DiscoveredMonitor; error: string }> = [];
  for (const suggestion of requested) {
    if (existing.has(monitorKey(suggestion))) {
      skipped.push(suggestion);
      continue;
    }
    if (!monitorQuotaAvailable(req.currentTenant!.id, created.length)) {
      errors.push({ monitor: suggestion, error: "Organization monitor limit reached." });
      continue;
    }
    const parsedMonitor = monitorInputSchema.safeParse(monitorFromDiscovery(suggestion));
    if (!parsedMonitor.success) {
      errors.push({ monitor: suggestion, error: parsedMonitor.error.issues[0]?.message ?? "Invalid monitor." });
      continue;
    }
    const monitor = monitors.create({ ...parsedMonitor.data, tenantId: req.currentTenant!.id });
    existing.add(monitorKey(monitor));
    created.push(monitor);
  }
  if (created.length) {
    const imported = new Set(created.map(monitorKey));
    appSettings.set("discovery", { ...settings, suggestions: settings.suggestions.filter((item) => !imported.has(monitorKey(item))) }, req.currentTenant!.id);
  }
  res.status(errors.length ? 207 : 201).json({ imported: created.length, skipped: skipped.length, errors, monitors: created });
});

// A backup file is a copy of the whole database, with every organization, user
// and stored secret in it, so only platform administrators may list, create,
// download or delete backup files.
const backupNotFound = "Backup not found. Reload the list; the file may have been removed by the retention setting.";

opsRoutes.get("/backups", requireAdmin, (_req, res) => res.json(listBackups()));
opsRoutes.post("/backups/run", requireAdmin, requireTenantRole("owner", "admin"), (req, res) => {
  const settings = appSettings.backups(req.currentTenant!.id);
  const backup = createBackup(settings);
  appSettings.set("backups", { ...settings, lastRunAt: new Date().toISOString() }, req.currentTenant!.id);
  res.status(201).json(backup);
});
opsRoutes.get("/backups/:name", requireAdmin, (req, res) => {
  const file = findBackupPath(req.params.name);
  if (!file) return res.status(404).json({ error: backupNotFound });
  res.download(file);
});
opsRoutes.delete("/backups/:name", requireAdmin, (req, res) => {
  if (!findBackupPath(req.params.name)) return res.status(404).json({ error: backupNotFound });
  deleteBackup(req.params.name);
  res.status(204).end();
});

opsRoutes.get("/api-tokens", requireAdmin, (_req, res) => res.json(apiTokens.list().map(publicToken)));
opsRoutes.post("/api-tokens", requireAdmin, (req, res) => {
  const parsed = tokenSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid token." });
  const plain = createPlainApiToken();
  const token = apiTokens.create(parsed.data.name, hashToken(plain), parsed.data.scopes, req.user!.id);
  res.status(201).json({ ...publicToken(token), token: plain });
});
opsRoutes.delete("/api-tokens/:id", requireAdmin, (req, res) => {
  apiTokens.delete(req.params.id);
  res.status(204).end();
});

opsRoutes.get("/deliveries", (req, res) => res.json(deliveries.list(req.currentTenant!.id)));
opsRoutes.get("/audit-log", requireTenantRole("owner", "admin"), (req, res) => {
  const entries = auditLogs.list(req.currentTenant!.id, Number(req.query.limit ?? 100));
  res.json(entries.map((entry) => ({ ...entry, actorEmail: entry.actorUserId ? (users.findById(entry.actorUserId)?.email ?? null) : null })));
});
opsRoutes.get("/reports/availability", (req, res) => res.json(availabilityReport(req.currentTenant!.id, Number(req.query.days ?? 30))));

opsRoutes.post("/incidents/:id/ack", (req, res) => {
  const parsed = z.object({
    assignee: z.string().max(120).optional().nullable(),
    comment: z.string().trim().max(2000).optional()
  }).safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: "Enter an assignee with at most 120 characters and a comment with at most 2000 characters." });
  if (adminMustComment(req) && !parsed.data.comment) return res.status(400).json({ error: "Admins must add a comment when acknowledging incidents." });
  const incident = incidents.acknowledge(req.params.id, req.currentTenant!.id, req.user!.email, parsed.data.assignee, parsed.data.comment);
  if (!incident) return res.status(404).json({ error: incidentNotFound });
  res.json(incident);
});

opsRoutes.post("/incidents/:id/notes", (req, res) => {
  const parsed = z.object({ text: z.string().trim().min(1).max(2000) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter a note with at most 2000 characters." });
  const incident = incidents.addNote(req.params.id, req.currentTenant!.id, req.user!.email, parsed.data.text);
  if (!incident) return res.status(404).json({ error: incidentNotFound });
  res.json(incident);
});

const incidentNotFound = "Incident not found in this organization. Reload the monitor; the incident may have been removed together with its monitor.";

const saveSetting = (req: any, res: any, key: string, schema: z.ZodTypeAny) => {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid settings." });
  appSettings.set(key, parsed.data, req.currentTenant.id);
  res.json(parsed.data);
};

const adminMustComment = (req: any) =>
  req.user?.role === "super_admin" || req.user?.role === "admin" || req.tenantRole === "owner" || req.tenantRole === "admin";

const maintenanceSchema = z.object({
  windows: z.array(z.object({
    id: z.string().default(() => id()),
    name: z.string().min(1).max(120),
    tags: z.array(z.string().min(1).max(40)),
    window: z.string().min(1).max(200),
    enabled: z.boolean()
  })).default([])
});

const tlsPolicySchema = z.object({
  profile: z.enum(["modern", "strict", "legacy"]),
  minimumTlsVersion: z.enum(["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]),
  weakCipherPenalty: z.number().int().min(0).max(80),
  requireSan: z.boolean(),
  intensiveScan: z.boolean().default(true)
});

const sslLabsSchema = z.object({
  enabled: z.boolean(),
  registeredEmail: z.string().trim().email().or(z.literal("")),
  intervalHours: z.number().int().min(24).max(720).default(24),
  maxAgeHours: z.number().int().min(1).max(720).default(24),
  timeoutSeconds: z.number().int().min(15).max(300).default(90),
  startNewScans: z.boolean().default(false),
  publishResults: z.boolean().default(false)
});

const sslLabsRegistrationSchema = z.object({
  firstName: z.string().trim().min(1).max(120),
  lastName: z.string().trim().min(1).max(120),
  email: z.string().trim().email().max(255).transform((email) => email.toLowerCase()),
  organization: z.string().trim().min(1).max(180)
});

const sslLabsTriggerSchema = z.object({
  monitorId: z.string().uuid().optional(),
  host: z.string().trim().max(253).optional(),
  startNewScan: z.boolean().default(true)
}).refine((value) => value.monitorId || value.host, { message: "Monitor or host is required." });

const discoverySchema = z.object({
  enabled: z.boolean(),
  intervalHours: z.number().int().min(1).max(720),
  domains: z.array(z.string().trim().min(1).max(253)),
  suggestions: z.array(z.any()).default([]),
  lastRunAt: z.string().nullable().optional()
});

const discoveredMonitorSchema = z.object({
  name: z.string().trim().min(1).max(120),
  host: z.string().trim().min(1).max(253),
  port: z.number().int().min(1).max(65535),
  type: z.enum(monitorTypes),
  tags: z.array(z.string().trim().min(1).max(40)).default([])
});

const backupsSchema = z.object({
  enabled: z.boolean(),
  intervalHours: z.number().int().min(1).max(720),
  keep: z.number().int().min(1).max(100),
  lastRunAt: z.string().nullable().optional()
});

const tokenSchema = z.object({
  name: z.string().trim().min(1).max(120),
  scopes: z.array(z.enum(["read", "write"])).default(["read"])
});

const publicToken = (token: any) => ({ id: token.id, name: token.name, scopes: token.scopes, createdAt: token.createdAt, lastUsedAt: token.lastUsedAt });

const availabilityReport = (tenantId: string, days: number) => {
  const cutoff = Date.now() - Math.max(1, Math.min(days, 3650)) * 86_400_000;
  return monitors.list(tenantId).map((monitor) => {
    const checks = results.list(monitor.id, 2000).filter((result) => new Date(result.checkedAt).getTime() >= cutoff);
    const ok = checks.filter((result) => result.status === "OK").length;
    const monitorIncidents = incidents.listForMonitor(monitor.id, 200).filter((incident) => new Date(incident.startedAt).getTime() >= cutoff);
    const resolved = monitorIncidents.filter((incident) => incident.resolvedAt);
    const mttrMinutes = resolved.length ? Math.round(resolved.reduce((sum, incident) => sum + (new Date(incident.resolvedAt!).getTime() - new Date(incident.startedAt).getTime()) / 60_000, 0) / resolved.length) : null;
    return { monitorId: monitor.id, name: monitor.name, tags: monitor.tags, checks: checks.length, availability: checks.length ? Math.round((ok / checks.length) * 10_000) / 100 : null, incidents: monitorIncidents.length, mttrMinutes };
  });
};

const monitorKey = (monitor: Pick<Monitor | DiscoveredMonitor, "host" | "port" | "type">) =>
  `${monitor.host.toLowerCase()}:${monitor.port}:${monitor.type}`;

const monitorFromDiscovery = (item: DiscoveredMonitor) => ({
  name: item.name,
  host: item.host,
  port: item.port,
  type: item.type,
  enabled: true,
  intervalSeconds: 3600,
  timeoutSeconds: 10,
  warningDays: 30,
  criticalDays: 7,
  gracePeriodSeconds: 0,
  sniEnabled: true,
  sniHost: null,
  validateCertificate: true,
  allowSelfSigned: false,
  tags: item.tags,
  notes: null,
  owner: null,
  notificationChannelIds: [],
  notificationRecipients: {},
  config: item.type === "https" && item.port === 443 ? { sslLabsEnabled: false } : {},
  maintenanceWindows: null
});

const monitorQuotaAvailable = (tenantId: string, pending = 0) => {
  const tenant = tenants.get(tenantId);
  return !tenant || tenant.monitorLimit <= 0 || monitors.list(tenantId).length + pending < tenant.monitorLimit;
};

const registerWithSslLabs = async (payload: z.infer<typeof sslLabsRegistrationSchema>) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch("https://api.ssllabs.com/api/v4/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    const text = await response.text();
    const body = parseProviderBody(text);
    if (!response.ok) throw new Error(providerError(response.status, body, text));
    return { status: response.status, body };
  } finally {
    clearTimeout(timeout);
  }
};

const parseProviderBody = (text: string) => {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text.slice(0, 500);
  }
};

const providerError = (status: number, body: unknown, text: string) => {
  if (body && typeof body === "object" && "message" in body) return `SSL Labs registration failed with HTTP ${status}: ${String((body as { message?: unknown }).message)}`;
  const detail = typeof body === "string" ? body : text;
  return `SSL Labs registration failed with HTTP ${status}${detail ? `: ${detail.slice(0, 180)}` : "."}`;
};

import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { id } from "../utils/id.js";
import { nowIso } from "../utils/time.js";
import { env } from "../config/env.js";
import { alerts, appSettings, auditLogs, channels, incidents, monitors, results, subscriptions, teamMemberships, teams, tenantInvites, tenants, userAlerts, users } from "../storage/repositories.js";
import { testChannel } from "../notifications/service.js";
import { NotificationTargetError } from "../notifications/delivery.js";
import { createImpersonationSession, requireSuperAdmin, requireTenantRole, setSessionCookie } from "../auth/auth.js";
import { passwordRule } from "../auth/passwords.js";
import { discoverMonitors } from "../checks/discovery.js";
import rootPackage from "../../../../package.json" with { type: "json" };

export const systemRoutes = Router();

// Every list and change below stays inside the organization selected for the request.
systemRoutes.get("/status", (req, res) => {
  const all = monitors.list(req.currentTenant!.id);
  const counts = all.reduce<Record<string, number>>((acc, monitor) => {
    acc[monitor.lastStatus] = (acc[monitor.lastStatus] ?? 0) + 1;
    return acc;
  }, {});
  res.json({
    total: all.length,
    ok: counts.OK ?? 0,
    warning: counts.WARNING ?? 0,
    critical: counts.CRITICAL ?? 0,
    down: counts.DOWN ?? 0,
    paused: counts.PAUSED ?? 0,
    unknown: counts.UNKNOWN ?? 0,
    latestResults: Object.values(results.latestByMonitor(req.currentTenant!.id)).slice(0, 10)
  });
});

systemRoutes.get("/alerts", (req, res) => res.json(alerts.list(req.currentTenant!.id)));
systemRoutes.get("/incidents", (req, res) => res.json(incidents.list(req.currentTenant!.id)));
systemRoutes.get("/subscriptions", (req, res) => res.json(subscriptions.list(req.currentTenant!.id)));
systemRoutes.delete("/subscriptions/:id", requireTenantRole("owner", "admin"), (req, res) => {
  if (!subscriptions.delete(req.params.id, req.currentTenant!.id)) return res.status(404).json({ error: "Subscription not found in this organization. Reload the list; it may have been removed already." });
  res.status(204).end();
});
systemRoutes.get("/health", (_req, res) => res.json({ ok: true }));
systemRoutes.get("/version", (_req, res) => res.json({ name: rootPackage.name, version: rootPackage.version }));
systemRoutes.get("/tenants", (req, res) => res.json(req.tenantMemberships?.map(publicMembership) ?? []));
systemRoutes.post("/tenants", (req, res) => {
  const parsed = z.object({ name: z.string().trim().min(2).max(120) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Organization name is required." });
  const tenant = tenants.create(parsed.data.name, req.user!.id);
  res.status(201).json({ tenantId: tenant.id, role: "owner", tenant });
});
systemRoutes.get("/tenants/:id/members", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  res.json(tenants.members(req.currentTenant!.id).map(publicMember));
});
systemRoutes.post("/tenants/:id/members", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const parsed = memberSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid member." });
  if (!canAssignRole(req, parsed.data.role)) return res.status(403).json({ error: "Only organization owners can assign owner rights." });
  const user = users.findByEmail(parsed.data.email);
  if (!user) return res.status(404).json({ error: "User must exist before it can be added to an organization." });
  const tenant = tenants.get(req.currentTenant!.id);
  if (tenant && tenant.userLimit > 0 && tenants.members(tenant.id).length >= tenant.userLimit) return res.status(402).json({ error: "Organization user limit reached." });
  tenants.addMember(req.currentTenant!.id, user.id, parsed.data.role);
  res.status(201).json(publicMember(tenants.members(req.currentTenant!.id).find((item) => item.userId === user.id)!));
});
systemRoutes.put("/tenants/:id/members/:userId", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const parsed = updateMemberSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid member update." });
  if (parsed.data.role && !canAssignRole(req, parsed.data.role)) return res.status(403).json({ error: "Only organization owners can assign owner rights." });
  const current = tenants.members(req.currentTenant!.id).find((item) => item.userId === req.params.userId);
  if (!current) return res.status(404).json({ error: "Member not found." });
  if (current.role === "owner" && req.tenantRole !== "owner") return res.status(403).json({ error: "Only organization owners can manage owners." });
  if (current.role === "owner" && parsed.data.role && parsed.data.role !== "owner" && tenants.activeOwnerCount(req.currentTenant!.id) <= 1) return res.status(409).json({ error: "An organization must keep at least one active owner." });
  if (req.params.userId === req.user!.id && parsed.data.role && parsed.data.role !== "owner" && req.tenantRole === "owner") return res.status(409).json({ error: "You cannot downgrade your own owner membership." });
  if (parsed.data.role) tenants.updateMember(req.currentTenant!.id, req.params.userId, parsed.data.role);
  const member = tenants.members(req.currentTenant!.id).find((item) => item.userId === req.params.userId);
  if (!member) return res.status(404).json({ error: "Member not found." });
  res.json(publicMember(member));
});
systemRoutes.delete("/tenants/:id/members/:userId", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  if (req.params.userId === req.user!.id) return res.status(409).json({ error: "You cannot remove your own organization membership." });
  const current = tenants.members(req.currentTenant!.id).find((item) => item.userId === req.params.userId);
  if (!current) return res.status(404).json({ error: "Member not found." });
  if (current.role === "owner" && req.tenantRole !== "owner") return res.status(403).json({ error: "Only organization owners can remove owners." });
  if (current.role === "owner" && tenants.activeOwnerCount(req.currentTenant!.id) <= 1) return res.status(409).json({ error: "An organization must keep at least one active owner." });
  userAlerts.deleteForUser(req.currentTenant!.id, req.params.userId);
  tenants.removeMember(req.currentTenant!.id, req.params.userId);
  res.status(204).end();
});
systemRoutes.get("/tenants/:id/teams", (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  res.json(teams.listForUser(req.currentTenant!.id, req.user!.id, req.tenantRole!));
});
systemRoutes.post("/tenants/:id/teams", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const parsed = teamSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid team." });
  const tenant = tenants.get(req.currentTenant!.id);
  if (tenant?.teamLimit && teams.list(req.currentTenant!.id, true).length >= tenant.teamLimit) return res.status(402).json({ error: "Organization team limit reached." });
  const team = teams.create(req.currentTenant!.id, parsed.data.name, parsed.data.description, parsed.data.visibility, req.user!.id);
  auditLogs.record({ tenantId: req.currentTenant!.id, teamId: team.id, actorUserId: req.user!.id, action: "team.created", metadata: { name: team.name, visibility: team.visibility } });
  res.status(201).json(team);
});
systemRoutes.get("/tenants/:id/teams/:teamId", (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const team = teams.get(req.currentTenant!.id, req.params.teamId);
  if (!team || !canSeeTeam(req, team.id, team.visibility)) return res.status(404).json({ error: "Team not found." });
  res.json(team);
});
systemRoutes.put("/tenants/:id/teams/:teamId", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const parsed = updateTeamSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid team." });
  const team = teams.update(req.currentTenant!.id, req.params.teamId, parsed.data);
  if (!team) return res.status(404).json({ error: "Team not found." });
  auditLogs.record({ tenantId: req.currentTenant!.id, teamId: team.id, actorUserId: req.user!.id, action: "team.updated", metadata: { name: team.name, status: team.status, visibility: team.visibility } });
  res.json(team);
});
systemRoutes.delete("/tenants/:id/teams/:teamId", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const team = teams.archive(req.currentTenant!.id, req.params.teamId);
  if (!team) return res.status(404).json({ error: "Team not found." });
  auditLogs.record({ tenantId: req.currentTenant!.id, teamId: team.id, actorUserId: req.user!.id, action: "team.archived", metadata: { name: team.name } });
  res.status(204).end();
});
systemRoutes.get("/tenants/:id/teams/:teamId/members", (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const team = teams.get(req.currentTenant!.id, req.params.teamId);
  if (!team || !canSeeTeam(req, team.id, team.visibility)) return res.status(404).json({ error: "Team not found." });
  res.json(teamMemberships.list(req.currentTenant!.id, team.id));
});
systemRoutes.post("/tenants/:id/teams/:teamId/members", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const parsed = teamMemberSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid team member." });
  const user = users.findByEmail(parsed.data.email);
  if (!user) return res.status(404).json({ error: "User must exist before it can be added to a team." });
  const member = teamMemberships.add(req.currentTenant!.id, req.params.teamId, user.id, parsed.data.role);
  if (!member) return res.status(422).json({ error: "User must be an active organization member before joining a team." });
  auditLogs.record({ tenantId: req.currentTenant!.id, teamId: req.params.teamId, actorUserId: req.user!.id, targetUserId: user.id, action: "team.member_added", metadata: { role: parsed.data.role } });
  res.status(201).json(member);
});
systemRoutes.put("/tenants/:id/teams/:teamId/members/:userId", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const parsed = updateTeamMemberSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid team member update." });
  const current = teamMemberships.get(req.currentTenant!.id, req.params.teamId, req.params.userId);
  if (!current) return res.status(404).json({ error: "Team member not found." });
  if (current.role === "team_owner" && parsed.data.role !== "team_owner" && teamMemberships.activeOwnerCount(req.currentTenant!.id, req.params.teamId) <= 1) return res.status(409).json({ error: "A team must keep at least one active owner." });
  const member = parsed.data.role ? teamMemberships.updateRole(req.currentTenant!.id, req.params.teamId, req.params.userId, parsed.data.role) : current;
  if (parsed.data.status) teamMemberships.setStatus(req.currentTenant!.id, req.params.teamId, req.params.userId, parsed.data.status);
  auditLogs.record({ tenantId: req.currentTenant!.id, teamId: req.params.teamId, actorUserId: req.user!.id, targetUserId: req.params.userId, action: "team.member_updated", metadata: parsed.data });
  res.json(member);
});
systemRoutes.delete("/tenants/:id/teams/:teamId/members/:userId", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const current = teamMemberships.get(req.currentTenant!.id, req.params.teamId, req.params.userId);
  if (!current) return res.status(404).json({ error: "Team member not found." });
  if (current.role === "team_owner" && teamMemberships.activeOwnerCount(req.currentTenant!.id, req.params.teamId) <= 1) return res.status(409).json({ error: "A team must keep at least one active owner." });
  teamMemberships.remove(req.currentTenant!.id, req.params.teamId, req.params.userId);
  auditLogs.record({ tenantId: req.currentTenant!.id, teamId: req.params.teamId, actorUserId: req.user!.id, targetUserId: req.params.userId, action: "team.member_removed", metadata: {} });
  res.status(204).end();
});
systemRoutes.get("/tenants/:id/invites", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  res.json(tenantInvites.list(req.currentTenant!.id).map(publicInvite));
});
systemRoutes.post("/tenants/:id/invites", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  const parsed = memberSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid invitation." });
  if (!canAssignRole(req, parsed.data.role)) return res.status(403).json({ error: "Only organization owners can invite owners." });
  if (parsed.data.teamId && !teams.get(req.currentTenant!.id, parsed.data.teamId)) return res.status(404).json({ error: "Team not found in this organization." });
  const tenant = tenants.get(req.currentTenant!.id);
  const memberCount = tenants.members(req.currentTenant!.id).length;
  const inviteCount = tenantInvites.list(req.currentTenant!.id).length;
  if (tenant && tenant.userLimit > 0 && memberCount + inviteCount >= tenant.userLimit) return res.status(402).json({ error: "Organization user limit reached." });

  const user = users.findByEmail(parsed.data.email);
  if (user) {
    tenants.addMember(req.currentTenant!.id, user.id, parsed.data.role);
    if (parsed.data.teamId) teamMemberships.add(req.currentTenant!.id, parsed.data.teamId, user.id, parsed.data.teamRole);
    const member = tenants.members(req.currentTenant!.id).find((item) => item.userId === user.id);
    return res.status(201).json({ member: member ? publicMember(member) : null, invite: null });
  }

  const existing = tenantInvites.list(req.currentTenant!.id).find((item) => item.email === parsed.data.email && (item.teamId ?? "") === (parsed.data.teamId ?? ""));
  const invite = existing ?? tenantInvites.create(req.currentTenant!.id, parsed.data.email, parsed.data.role, req.user!.id, parsed.data.teamId, parsed.data.teamRole);
  res.status(existing ? 200 : 201).json({ member: null, invite: publicInvite(invite) });
});
systemRoutes.delete("/tenants/:id/invites/:inviteId", requireTenantRole("owner", "admin"), (req, res) => {
  if (req.params.id !== req.currentTenant!.id) return res.status(403).json({ error: "Select the organization first." });
  tenantInvites.delete(req.params.inviteId, req.currentTenant!.id);
  res.status(204).end();
});
systemRoutes.get("/me/alert-settings", (req, res) => res.json(userAlerts.get(req.currentTenant!.id, req.user!.id)));
systemRoutes.put("/me/alert-settings", (req, res) => {
  const parsed = userAlertSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid personal alert settings." });
  res.json(userAlerts.upsert({ ...parsed.data, tenantId: req.currentTenant!.id, userId: req.user!.id, updatedAt: nowIso() }));
});
systemRoutes.get("/settings/ct-watch", (req, res) => res.json(appSettings.ctWatch(req.currentTenant!.id)));
systemRoutes.put("/settings/ct-watch", requireTenantRole("owner", "admin"), (req, res) => {
  const parsed = ctWatchSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid CT watch settings." });
  appSettings.set("ctWatch", parsed.data, req.currentTenant!.id);
  res.json(parsed.data);
});
// Express 4 does not catch a rejected handler, so a failed query at crt.sh is answered here.
systemRoutes.post("/ct-watch/check", async (req, res) => {
  try {
    res.json(await checkCtWatch(req.currentTenant!.id));
  } catch {
    res.status(502).json({ error: "crt.sh could not be reached, so the certificate transparency check did not run. Try again later; if it keeps failing, check that the crt.watch server can reach crt.sh." });
  }
});
systemRoutes.post("/discover", async (req, res) => {
  const parsed = discoverSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid discovery request." });
  res.json({ monitors: await discoverMonitors(parsed.data.domain) });
});
systemRoutes.get("/settings/alerting", (req, res) => res.json(appSettings.alerting(req.currentTenant!.id)));
systemRoutes.put("/settings/alerting", requireTenantRole("owner", "admin"), (req, res) => {
  const parsed = alertingSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid alerting settings." });
  appSettings.set("alerting", parsed.data, req.currentTenant!.id);
  res.json(parsed.data);
});
systemRoutes.get("/settings/smtp", (req, res) => res.json(redactConfig(appSettings.smtp(req.currentTenant!.id))));
systemRoutes.put("/settings/smtp", requireTenantRole("owner", "admin"), (req, res) => {
  const current = appSettings.smtp(req.currentTenant!.id);
  const parsed = smtpSchema.safeParse({ ...current, ...req.body });
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid SMTP settings." });
  const next = { ...parsed.data, password: parsed.data.password === "********" ? current.password : parsed.data.password };
  appSettings.set("smtp", next, req.currentTenant!.id);
  res.json(redactConfig(next));
});
systemRoutes.get("/settings/retention", (req, res) => res.json(appSettings.retention(req.currentTenant!.id)));
systemRoutes.put("/settings/retention", requireTenantRole("owner", "admin"), (req, res) => {
  const parsed = retentionSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid retention settings." });
  appSettings.set("retention", parsed.data, req.currentTenant!.id);
  res.json(parsed.data);
});
systemRoutes.get("/notification-routes", (req, res) => res.json(appSettings.notificationRoutes(req.currentTenant!.id)));
systemRoutes.put("/notification-routes", requireTenantRole("owner", "admin"), (req, res) => {
  const parsed = z.array(routeSchema).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid notification routes." });
  appSettings.set("notificationRoutes", parsed.data, req.currentTenant!.id);
  res.json(parsed.data);
});
systemRoutes.get("/notification-channels", (req, res) => res.json(channels.list(req.currentTenant!.id).map(redactChannel)));

systemRoutes.post("/notification-channels", requireTenantRole("owner", "admin"), (req, res) => {
  const parsed = channelSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid channel." });
  const now = nowIso();
  const existing = parsed.data.id ? channels.get(parsed.data.id, req.currentTenant!.id) : null;
  const channel = {
    ...parsed.data,
    tenantId: req.currentTenant!.id,
    id: parsed.data.id ?? id(),
    config: mergeMaskedConfig(existing?.config ?? {}, parsed.data.config ?? {}),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now
  };
  // An id of another organization's channel writes nothing.
  if (!channels.upsert(channel)) return res.status(404).json({ error: "Notification channel not found in this organization. Reload the page and save the channel again." });
  res.status(201).json(redactChannel(channel));
});

systemRoutes.delete("/notification-channels/:id", requireTenantRole("owner", "admin"), (req, res) => {
  channels.delete(req.params.id, req.currentTenant!.id);
  res.status(204).end();
});

// Testing sends a message with the stored or the submitted settings, so it needs the same role as saving them.
systemRoutes.post("/notification-channels/test", requireTenantRole("owner", "admin"), async (req, res) => {
  const channel = req.body.id ? channels.get(String(req.body.id), req.currentTenant!.id) : { ...req.body, tenantId: req.currentTenant!.id };
  if (!channel) return res.status(404).json({ error: "Notification channel not found in this organization. Reload the page and test the channel again." });
  // Express 4 does not catch a rejected handler, so a failed test must be answered here.
  try {
    await testChannel(channel);
    res.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The test notification could not be delivered. Check the channel settings and try again.";
    res.status(error instanceof NotificationTargetError ? 400 : 502).json({ error: message });
  }
});

systemRoutes.get("/platform-settings", requireSuperAdmin, (_req, res) => {
  res.json(appSettings.platform());
});

systemRoutes.put("/platform-settings", requireSuperAdmin, (req, res) => {
  const parsed = platformSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid platform settings." });
  appSettings.set("platform", parsed.data);
  res.json(parsed.data);
});

systemRoutes.get("/users", requireSuperAdmin, (_req, res) => {
  res.json(users.list().map(publicUser));
});

systemRoutes.post("/users", requireSuperAdmin, async (req, res) => {
  const parsed = userSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid user." });
  if (users.findByEmail(parsed.data.email)) return res.status(409).json({ error: "A user with this email already exists." });
  const user = users.create(parsed.data.email, await bcrypt.hash(parsed.data.password, 12), parsed.data.role);
  tenants.addMember(req.currentTenant!.id, user.id, parsed.data.tenantRole);
  res.status(201).json(publicUser(user));
});

systemRoutes.put("/users/:id", requireSuperAdmin, async (req, res) => {
  const parsed = updateUserSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid user." });
  if (req.user?.id === req.params.id && parsed.data.role !== "super_admin") return res.status(409).json({ error: "You cannot remove your own super admin role." });
  const hash = parsed.data.password ? await bcrypt.hash(parsed.data.password, 12) : undefined;
  users.update(req.params.id, parsed.data.role, hash);
  res.json({ ok: true });
});

systemRoutes.delete("/users/:id", requireSuperAdmin, (req, res) => {
  if (req.user?.id === req.params.id) return res.status(409).json({ error: "You cannot delete your own user." });
  users.delete(req.params.id);
  res.status(204).end();
});

systemRoutes.post("/users/:id/impersonate", requireSuperAdmin, (req, res) => {
  const result = createImpersonationSession(req.params.id, req.user!.id);
  if (!result) return res.status(404).json({ error: "User cannot be impersonated." });
  setSessionCookie(res, result.token);
  res.json({ user: result.user, csrfToken: result.csrfToken, impersonator: result.impersonator, tenants: tenants.forUser(result.user.id).map(publicMembership) });
});

const channelSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1).max(100),
  type: z.enum(["email", "pushover", "webhook", "discord", "slack", "telegram", "gotify", "ntfy", "teams", "mattermost", "matrix", "pagerduty", "opsgenie"]),
  enabled: z.boolean().default(true),
  config: z.record(z.unknown()).default({})
});

const alertingSchema = z.object({
  resendAfterHours: z.number().int().min(1).max(720),
  recoveryEnabled: z.boolean(),
  certificateChangeAlerts: z.boolean().default(true),
  dnsChangeAlerts: z.boolean().default(false),
  tlsDeteriorationAlerts: z.boolean().default(true),
  tlsDeteriorationThreshold: z.number().int().min(1).max(50).default(5),
  quietHoursEnabled: z.boolean(),
  quietStart: z.string().regex(/^\d{2}:\d{2}$/),
  quietEnd: z.string().regex(/^\d{2}:\d{2}$/),
  quietSuppressCritical: z.boolean(),
  flappingThreshold: z.number().int().min(2).max(20).default(4)
});

const retentionSchema = z.object({
  checkResultsDays: z.number().int().min(1).max(3650),
  alertHistoryDays: z.number().int().min(1).max(3650)
});

const routeSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(100),
  tags: z.array(z.string().min(1).max(40)),
  severities: z.array(z.enum(["info", "warning", "critical", "recovery"])),
  channelIds: z.array(z.string()),
  recipients: z.record(z.string().max(2000)).default({}),
  delayMinutes: z.number().int().min(0).max(10_080).default(0),
  enabled: z.boolean()
});

const memberSchema = z.object({
  email: z.string().trim().email().transform((email) => email.toLowerCase()),
  role: z.enum(["owner", "admin", "member", "viewer"]).default("viewer"),
  teamId: z.string().uuid().optional().or(z.literal("")).transform((value) => value || undefined),
  teamRole: z.enum(["team_owner", "team_admin", "team_member"]).default("team_member")
});

const updateMemberSchema = z.object({
  role: z.enum(["owner", "admin", "member", "viewer"]).optional()
});

const teamSchema = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(1000).default(""),
  visibility: z.enum(["private", "tenant_visible"]).default("tenant_visible")
});

const updateTeamSchema = teamSchema.extend({
  status: z.enum(["active", "archived"]).default("active")
});

const teamMemberSchema = z.object({
  email: z.string().trim().email().transform((email) => email.toLowerCase()),
  role: z.enum(["team_owner", "team_admin", "team_member"]).default("team_member")
});

const updateTeamMemberSchema = z.object({
  role: z.enum(["team_owner", "team_admin", "team_member"]).optional(),
  status: z.enum(["active", "disabled"]).optional()
});

const userAlertSchema = z.object({
  enabled: z.boolean(),
  tags: z.array(z.string().trim().min(1).max(40)).default([]),
  severities: z.array(z.enum(["info", "warning", "recovery"])).default(["warning", "recovery"]),
  channelIds: z.array(z.string().uuid()).default([]),
  recipients: z.record(z.string().max(2000)).default({})
});

const ctWatchSchema = z.object({
  enabled: z.boolean(),
  domains: z.array(z.string().trim().min(1).max(253)).default([]),
  lastSeen: z.record(z.string()).default({})
});

const discoverSchema = z.object({
  domain: z.string().trim().min(1).max(253)
});

const userSchema = z.object({
  email: z.string().trim().email().transform((email) => email.toLowerCase()),
  password: passwordRule(),
  role: z.enum(["super_admin", "admin", "viewer"]).default("viewer"),
  tenantRole: z.enum(["owner", "admin", "member", "viewer"]).default("viewer")
});

const updateUserSchema = z.object({
  password: passwordRule().optional().or(z.literal("")),
  role: z.enum(["super_admin", "admin", "viewer"])
}).transform((value) => ({ ...value, password: value.password || undefined }));

const platformSchema = z.object({
  publicRegistrationEnabled: z.boolean()
});

const smtpSchema = z.object({
  host: z.string().max(255),
  port: z.number().int().min(1).max(65535),
  username: z.string().max(255),
  password: z.string().max(1000),
  from: z.string().max(255),
  secure: z.boolean(),
  starttls: z.boolean()
});

const redactConfig = (config: object) =>
  Object.fromEntries(Object.entries(config ?? {}).map(([key, value]) =>
    /pass|token|secret|key/i.test(key) ? [key, value ? "********" : ""] : [key, value]
  ));

const mergeMaskedConfig = (previous: Record<string, unknown>, next: Record<string, unknown>) =>
  Object.fromEntries(Object.entries(next).map(([key, value]) => [
    key,
    value === "********" ? previous?.[key] : value
  ]));

const redactChannel = (channel: any) => ({
  ...channel,
  config: redactConfig(channel.config)
});

const publicUser = (user: any) => ({ id: user.id, email: user.email, role: user.role, createdAt: user.createdAt });
const publicMembership = (membership: any) => ({ tenantId: membership.tenantId, role: membership.role, tenant: membership.tenant });
const publicMember = (membership: any) => ({ userId: membership.userId, email: membership.userEmail, role: membership.role, status: membership.status ?? "active", createdAt: membership.createdAt });
const publicInvite = (invite: any) => ({
  id: invite.id,
  tenantId: invite.tenantId,
  email: invite.email,
  role: invite.role,
  teamId: invite.teamId,
  teamRole: invite.teamRole,
  expiresAt: invite.expiresAt,
  createdAt: invite.createdAt,
  inviteUrl: isRawInviteToken(invite.token) ? `${env.baseUrl.replace(/\/$/, "")}/register?invite=${encodeURIComponent(invite.token)}` : ""
});

const canAssignRole = (req: any, role: string) => role !== "owner" || req.tenantRole === "owner";

const canSeeTeam = (req: any, teamId: string, visibility: string) =>
  req.tenantRole === "owner" || req.tenantRole === "admin" || visibility === "tenant_visible" || req.teamMemberships?.some((item: any) => item.teamId === teamId && item.status === "active");

const isRawInviteToken = (token: string) => /^[a-f0-9-]{24,64}$/i.test(token) && token.length !== 64;

const checkCtWatch = async (tenantId: string) => {
  const settings = appSettings.ctWatch(tenantId);
  const next = { ...settings, lastSeen: { ...settings.lastSeen } };
  const changes: Array<{ domain: string; newest: string; previous: string }> = [];
  if (!settings.enabled) return { enabled: false, changes };
  for (const domain of settings.domains) {
    const entries = await fetchCtEntries(domain);
    const newest = entries[0]?.id ?? "";
    if (newest && settings.lastSeen[domain] && settings.lastSeen[domain] !== newest) changes.push({ domain, newest, previous: settings.lastSeen[domain] });
    if (newest) next.lastSeen[domain] = newest;
  }
  appSettings.set("ctWatch", next, tenantId);
  return { enabled: true, changes, lastSeen: next.lastSeen };
};

const fetchCtEntries = async (domain: string) => {
  const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
  if (!response.ok) return [];
  const data = await response.json().catch(() => []);
  return Array.isArray(data) ? data.map((item: any) => ({ id: String(item.id ?? ""), name: String(item.name_value ?? ""), notBefore: String(item.not_before ?? "") })).sort((a, b) => b.id.localeCompare(a.id)) : [];
};

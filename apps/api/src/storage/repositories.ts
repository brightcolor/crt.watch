import { db, rowToApiToken, rowToAuditLog, rowToChannel, rowToDelivery, rowToIncident, rowToInvite, rowToMembership, rowToMonitor, rowToResult, rowToSubscription, rowToTeam, rowToTeamMembership, rowToTenant, rowToUser, rowToUserAlertSettings } from "./db.js";
import { createHash } from "node:crypto";
import { id } from "../utils/id.js";
import { addSecondsIso, nowIso } from "../utils/time.js";
import type { AlertingSettings, ApiToken, AuditLogEntry, BackupSettings, CheckResult, CtWatchSettings, DiscoverySettings, Incident, IncidentNote, MaintenanceSettings, Monitor, MonitorStatus, NotificationChannel, NotificationDelivery, NotificationRoute, PlatformSettings, RetentionSettings, SslLabsSettings, StatusPageSettings, StatusSubscription, SmtpSettings, Team, TeamMembership, TeamRole, TeamVisibility, Tenant, TenantInvite, TenantMembership, TenantRole, TlsPolicySettings, User, UserAlertSettings, UserRole } from "../types.js";
import { DEFAULT_TENANT_ID } from "../types.js";
import { decryptConfigSecrets, encryptConfigSecrets } from "../utils/secrets.js";

export const users = {
  count(): number {
    const row = db.prepare("SELECT COUNT(*) AS count FROM users").get() as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  },
  /** Platform administrators; the first-run setup stays open while there are none. */
  countAdmins(): number {
    const row = db.prepare("SELECT COUNT(*) AS count FROM users WHERE role IN ('super_admin', 'admin')").get() as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  },
  findByEmail(email: string): User | null {
    const row = db.prepare("SELECT * FROM users WHERE email = ?").get(email.toLowerCase());
    return row ? rowToUser(row) : null;
  },
  findById(userId: string): User | null {
    const row = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    return row ? rowToUser(row) : null;
  },
  list(): User[] {
    return db.prepare("SELECT * FROM users ORDER BY email").all().map(rowToUser);
  },
  create(email: string, passwordHash: string, role: UserRole): User {
    const createdAt = nowIso();
    const user = { id: id(), email: email.toLowerCase(), passwordHash, role, createdAt, mfaEnabled: false };
    db.prepare("INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)").run(user.id, user.email, user.passwordHash, user.role, user.createdAt);
    return user;
  },
  update(userId: string, role: UserRole, passwordHash?: string) {
    if (passwordHash) db.prepare("UPDATE users SET role = ?, password_hash = ? WHERE id = ?").run(role, passwordHash, userId);
    else db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, userId);
  },
  delete(userId: string) {
    db.prepare("DELETE FROM users WHERE id = ?").run(userId);
  },
  getMfaSecret(userId: string): string | null {
    const row = db.prepare("SELECT mfa_secret FROM users WHERE id = ?").get(userId) as { mfa_secret?: string | null } | undefined;
    return row?.mfa_secret ?? null;
  },
  setPendingMfaSecret(userId: string, encryptedSecret: string) {
    db.prepare("UPDATE users SET mfa_secret = ?, mfa_enabled = 0, mfa_backup_codes_json = '[]' WHERE id = ?").run(encryptedSecret, userId);
  },
  enableMfa(userId: string, backupCodeHashes: string[]) {
    db.prepare("UPDATE users SET mfa_enabled = 1, mfa_backup_codes_json = ? WHERE id = ?").run(JSON.stringify(backupCodeHashes), userId);
  },
  disableMfa(userId: string) {
    db.prepare("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_backup_codes_json = '[]' WHERE id = ?").run(userId);
  },
  consumeMfaBackupCode(userId: string, codeHash: string): boolean {
    const row = db.prepare("SELECT mfa_backup_codes_json FROM users WHERE id = ?").get(userId) as { mfa_backup_codes_json?: string } | undefined;
    const codes: string[] = row?.mfa_backup_codes_json ? JSON.parse(row.mfa_backup_codes_json) : [];
    if (!codes.includes(codeHash)) return false;
    db.prepare("UPDATE users SET mfa_backup_codes_json = ? WHERE id = ?").run(JSON.stringify(codes.filter((entry) => entry !== codeHash)), userId);
    return true;
  }
};

export const tenants = {
  list(): Tenant[] {
    return db.prepare("SELECT * FROM tenants WHERE deleted_at IS NULL ORDER BY name").all().map(rowToTenant);
  },
  get(tenantId: string): Tenant | null {
    const row = db.prepare("SELECT * FROM tenants WHERE id = ? AND deleted_at IS NULL").get(tenantId);
    return row ? rowToTenant(row) : null;
  },
  forUser(userId: string): TenantMembership[] {
    return db.prepare(`
      SELECT t.*, tm.id AS membership_id, tm.tenant_id, tm.user_id, tm.role,
        tm.status AS membership_status, tm.created_at, tm.updated_at AS membership_updated_at, u.email
      FROM tenant_memberships tm
      JOIN tenants t ON t.id = tm.tenant_id
      JOIN users u ON u.id = tm.user_id
      WHERE tm.user_id = ? AND tm.status = 'active' AND t.deleted_at IS NULL AND t.status IN ('active', 'trialing')
      ORDER BY t.name
    `).all(userId).map(rowToMembership);
  },
  members(tenantId: string): TenantMembership[] {
    return db.prepare(`
      SELECT t.*, tm.id AS membership_id, tm.tenant_id, tm.user_id, tm.role,
        tm.status AS membership_status, tm.created_at, tm.updated_at AS membership_updated_at, u.email
      FROM tenant_memberships tm
      JOIN tenants t ON t.id = tm.tenant_id
      JOIN users u ON u.id = tm.user_id
      WHERE tm.tenant_id = ? AND t.deleted_at IS NULL
      ORDER BY u.email
    `).all(tenantId).map(rowToMembership);
  },
  create(name: string, ownerUserId: string): Tenant {
    const createdAt = nowIso();
    const tenant = { id: id(), name, slug: uniqueSlug(slugify(name)), plan: "free" as const, status: "active" as const, monitorLimit: 50, userLimit: 5, teamLimit: 10, settings: {}, createdAt, updatedAt: createdAt, deletedAt: null };
    db.prepare(`
      INSERT INTO tenants (id, name, slug, plan, status, monitor_limit, user_limit, team_limit, settings_json, created_at, updated_at, deleted_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, NULL)
    `).run(tenant.id, tenant.name, tenant.slug, tenant.plan, tenant.status, tenant.monitorLimit, tenant.userLimit, tenant.teamLimit, tenant.createdAt, tenant.updatedAt);
    this.addMember(tenant.id, ownerUserId, "owner");
    teams.create(tenant.id, "General", "Default team for this organization.", "tenant_visible", ownerUserId);
    return tenant;
  },
  addMember(tenantId: string, userId: string, role: TenantRole) {
    const now = nowIso();
    db.prepare(`
      INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'active', ?, ?)
      ON CONFLICT(tenant_id, user_id) DO UPDATE SET role = excluded.role, status = 'active', updated_at = excluded.updated_at
    `).run(id(), tenantId, userId, role, now, now);
    const general = teams.bySlug(tenantId, "general");
    if (general) teamMemberships.add(tenantId, general.id, userId, role === "owner" || role === "admin" ? "team_owner" : "team_member");
  },
  updateMember(tenantId: string, userId: string, role: TenantRole) {
    db.prepare("UPDATE tenant_memberships SET role = ?, updated_at = ? WHERE tenant_id = ? AND user_id = ?").run(role, nowIso(), tenantId, userId);
  },
  setMemberStatus(tenantId: string, userId: string, status: "active" | "disabled") {
    db.prepare("UPDATE tenant_memberships SET status = ?, updated_at = ? WHERE tenant_id = ? AND user_id = ?").run(status, nowIso(), tenantId, userId);
    if (status !== "active") teamMemberships.disableForUser(tenantId, userId);
  },
  removeMember(tenantId: string, userId: string) {
    teamMemberships.disableForUser(tenantId, userId);
    db.prepare("DELETE FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?").run(tenantId, userId);
  },
  activeOwnerCount(tenantId: string): number {
    const row = db.prepare("SELECT COUNT(*) AS count FROM tenant_memberships WHERE tenant_id = ? AND role = 'owner' AND status = 'active'").get(tenantId) as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  }
};

export const tenantInvites = {
  list(tenantId: string): TenantInvite[] {
    return db.prepare(`
      SELECT * FROM tenant_invites
      WHERE tenant_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?
      ORDER BY created_at DESC
    `).all(tenantId, nowIso()).map(rowToInvite);
  },
  create(tenantId: string, email: string, role: TenantRole, invitedByUserId?: string, teamId?: string | null, teamRole?: TeamRole | null): TenantInvite {
    const rawToken = id().replaceAll("-", "");
    const now = nowIso();
    const invite = {
      id: id(),
      tenantId,
      email: email.toLowerCase(),
      role,
      token: rawToken,
      tokenHash: hashInviteToken(rawToken),
      teamId: teamId ?? null,
      teamRole: teamRole ?? null,
      invitedByUserId: invitedByUserId ?? null,
      acceptedAt: null,
      revokedAt: null,
      expiresAt: addSecondsIso(60 * 60 * 24 * 14),
      createdAt: now,
      updatedAt: now
    };
    db.prepare(`
      INSERT INTO tenant_invites (id, tenant_id, email, role, token, token_hash, team_id, team_role, invited_by_user_id, accepted_at, revoked_at, expires_at, created_at, updated_at)
      VALUES (@id, @tenantId, @email, @role, @tokenHash, @tokenHash, @teamId, @teamRole, @invitedByUserId, @acceptedAt, @revokedAt, @expiresAt, @createdAt, @updatedAt)
    `).run(invite);
    return invite;
  },
  findByToken(token: string): TenantInvite | null {
    const row = db.prepare("SELECT * FROM tenant_invites WHERE (token_hash = ? OR token = ?) AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?").get(hashInviteToken(token), token, nowIso());
    return row ? rowToInvite(row) : null;
  },
  accept(invite: TenantInvite, userId: string) {
    tenants.addMember(invite.tenantId, userId, invite.role);
    if (invite.teamId && invite.teamRole) teamMemberships.add(invite.tenantId, invite.teamId, userId, invite.teamRole);
    db.prepare("UPDATE tenant_invites SET accepted_at = ? WHERE id = ?").run(nowIso(), invite.id);
  },
  delete(inviteId: string, tenantId: string) {
    db.prepare("UPDATE tenant_invites SET revoked_at = ?, updated_at = ? WHERE id = ? AND tenant_id = ?").run(nowIso(), nowIso(), inviteId, tenantId);
  }
};

export const teams = {
  listForUser(tenantId: string, userId: string, tenantRole: TenantRole): Team[] {
    if (tenantRole === "owner" || tenantRole === "admin") return this.list(tenantId, true);
    return db.prepare(`
      SELECT DISTINCT t.* FROM teams t
      LEFT JOIN team_memberships tm ON tm.team_id = t.id AND tm.user_id = ? AND tm.status = 'active'
      WHERE t.tenant_id = ? AND t.deleted_at IS NULL AND (t.visibility = 'tenant_visible' OR tm.user_id IS NOT NULL)
      ORDER BY t.name
    `).all(userId, tenantId).map(rowToTeam);
  },
  list(tenantId: string, includeArchived = false): Team[] {
    return db.prepare(`
      SELECT * FROM teams
      WHERE tenant_id = ? AND deleted_at IS NULL ${includeArchived ? "" : "AND status = 'active'"}
      ORDER BY status, name
    `).all(tenantId).map(rowToTeam);
  },
  get(tenantId: string, teamId: string): Team | null {
    const row = db.prepare("SELECT * FROM teams WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL").get(teamId, tenantId);
    return row ? rowToTeam(row) : null;
  },
  bySlug(tenantId: string, slug: string): Team | null {
    const row = db.prepare("SELECT * FROM teams WHERE tenant_id = ? AND slug = ? AND deleted_at IS NULL").get(tenantId, slug);
    return row ? rowToTeam(row) : null;
  },
  create(tenantId: string, name: string, description: string, visibility: TeamVisibility, createdByUserId?: string | null): Team {
    const now = nowIso();
    const slug = uniqueTeamSlug(tenantId, slugify(name));
    const team: Team = { id: id(), tenantId, name, slug, description, visibility, status: "active", settings: {}, createdByUserId: createdByUserId ?? null, createdAt: now, updatedAt: now, deletedAt: null };
    db.prepare(`
      INSERT INTO teams (id, tenant_id, name, slug, description, visibility, status, settings_json, created_by_user_id, created_at, updated_at, deleted_at)
      VALUES (@id, @tenantId, @name, @slug, @description, @visibility, @status, @settingsJson, @createdByUserId, @createdAt, @updatedAt, @deletedAt)
    `).run({ ...team, settingsJson: JSON.stringify(team.settings) });
    if (createdByUserId) teamMemberships.add(tenantId, team.id, createdByUserId, "team_owner");
    return team;
  },
  update(tenantId: string, teamId: string, input: Pick<Team, "name" | "description" | "visibility" | "status">): Team | null {
    const existing = this.get(tenantId, teamId);
    if (!existing) return null;
    const slug = existing.name === input.name ? existing.slug : uniqueTeamSlug(tenantId, slugify(input.name), teamId);
    db.prepare(`
      UPDATE teams SET name = ?, slug = ?, description = ?, visibility = ?, status = ?, updated_at = ?
      WHERE id = ? AND tenant_id = ?
    `).run(input.name, slug, input.description, input.visibility, input.status, nowIso(), teamId, tenantId);
    return this.get(tenantId, teamId);
  },
  archive(tenantId: string, teamId: string): Team | null {
    const team = this.get(tenantId, teamId);
    if (!team) return null;
    db.prepare("UPDATE teams SET status = 'archived', updated_at = ? WHERE id = ? AND tenant_id = ?").run(nowIso(), teamId, tenantId);
    teamMemberships.disableForTeam(tenantId, teamId);
    return this.get(tenantId, teamId);
  },
  delete(tenantId: string, teamId: string) {
    db.prepare("UPDATE teams SET deleted_at = ?, status = 'archived', updated_at = ? WHERE id = ? AND tenant_id = ?").run(nowIso(), nowIso(), teamId, tenantId);
    teamMemberships.disableForTeam(tenantId, teamId);
  }
};

export const teamMemberships = {
  list(tenantId: string, teamId: string): TeamMembership[] {
    return db.prepare(`
      SELECT tm.*, u.email FROM team_memberships tm
      JOIN users u ON u.id = tm.user_id
      WHERE tm.tenant_id = ? AND tm.team_id = ?
      ORDER BY u.email
    `).all(tenantId, teamId).map(rowToTeamMembership);
  },
  activeForUser(tenantId: string, userId: string): TeamMembership[] {
    return db.prepare(`
      SELECT tm.id AS membership_id, tm.tenant_id AS membership_tenant_id,
        tm.team_id AS membership_team_id, tm.user_id, tm.role,
        tm.status AS membership_status, tm.created_at AS membership_created_at,
        tm.updated_at AS membership_updated_at, t.*, u.email
      FROM team_memberships tm
      JOIN teams t ON t.id = tm.team_id AND t.tenant_id = tm.tenant_id
      JOIN users u ON u.id = tm.user_id
      WHERE tm.tenant_id = ? AND tm.user_id = ? AND tm.status = 'active' AND t.status = 'active' AND t.deleted_at IS NULL
      ORDER BY t.name
    `).all(tenantId, userId).map(rowToTeamMembership);
  },
  get(tenantId: string, teamId: string, userId: string): TeamMembership | null {
    const row = db.prepare("SELECT tm.*, u.email FROM team_memberships tm JOIN users u ON u.id = tm.user_id WHERE tm.tenant_id = ? AND tm.team_id = ? AND tm.user_id = ?").get(tenantId, teamId, userId);
    return row ? rowToTeamMembership(row) : null;
  },
  add(tenantId: string, teamId: string, userId: string, role: TeamRole): TeamMembership | null {
    if (!teams.get(tenantId, teamId)) return null;
    if (!activeTenantMember(tenantId, userId)) return null;
    const now = nowIso();
    db.prepare(`
      INSERT INTO team_memberships (id, tenant_id, team_id, user_id, role, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
      ON CONFLICT(team_id, user_id) DO UPDATE SET role = excluded.role, status = 'active', updated_at = excluded.updated_at
    `).run(id(), tenantId, teamId, userId, role, now, now);
    return this.get(tenantId, teamId, userId);
  },
  updateRole(tenantId: string, teamId: string, userId: string, role: TeamRole): TeamMembership | null {
    db.prepare("UPDATE team_memberships SET role = ?, updated_at = ? WHERE tenant_id = ? AND team_id = ? AND user_id = ?").run(role, nowIso(), tenantId, teamId, userId);
    return this.get(tenantId, teamId, userId);
  },
  setStatus(tenantId: string, teamId: string, userId: string, status: "active" | "disabled") {
    db.prepare("UPDATE team_memberships SET status = ?, updated_at = ? WHERE tenant_id = ? AND team_id = ? AND user_id = ?").run(status, nowIso(), tenantId, teamId, userId);
  },
  remove(tenantId: string, teamId: string, userId: string) {
    db.prepare("DELETE FROM team_memberships WHERE tenant_id = ? AND team_id = ? AND user_id = ?").run(tenantId, teamId, userId);
  },
  disableForUser(tenantId: string, userId: string) {
    db.prepare("UPDATE team_memberships SET status = 'disabled', updated_at = ? WHERE tenant_id = ? AND user_id = ?").run(nowIso(), tenantId, userId);
  },
  disableForTeam(tenantId: string, teamId: string) {
    db.prepare("UPDATE team_memberships SET status = 'disabled', updated_at = ? WHERE tenant_id = ? AND team_id = ?").run(nowIso(), tenantId, teamId);
  },
  activeOwnerCount(tenantId: string, teamId: string): number {
    const row = db.prepare("SELECT COUNT(*) AS count FROM team_memberships WHERE tenant_id = ? AND team_id = ? AND role = 'team_owner' AND status = 'active'").get(tenantId, teamId) as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  }
};

export const auditLogs = {
  record(input: Omit<AuditLogEntry, "id" | "createdAt">) {
    db.prepare(`
      INSERT INTO audit_log (id, tenant_id, team_id, actor_user_id, target_user_id, action, entity_type, entity_id, metadata_json, details_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id(), input.tenantId ?? null, input.teamId ?? null, input.actorUserId ?? null, input.targetUserId ?? null, input.action, input.action.split(".")[0] ?? "system", input.teamId ?? input.tenantId ?? null, JSON.stringify(input.metadata), JSON.stringify(input.metadata), nowIso());
  },
  list(tenantId: string, limit = 100): AuditLogEntry[] {
    return db.prepare("SELECT * FROM audit_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?").all(tenantId, limit).map(rowToAuditLog);
  }
};

export const userAlerts = {
  get(tenantId: string, userId: string): UserAlertSettings {
    const row = db.prepare("SELECT * FROM user_alert_settings WHERE tenant_id = ? AND user_id = ?").get(tenantId, userId);
    return row ? rowToUserAlertSettings(row) : defaultUserAlerts(tenantId, userId);
  },
  list(tenantId: string): UserAlertSettings[] {
    return db.prepare("SELECT * FROM user_alert_settings WHERE tenant_id = ? AND enabled = 1").all(tenantId).map(rowToUserAlertSettings);
  },
  upsert(input: UserAlertSettings): UserAlertSettings {
    const next = {
      ...input,
      updatedAt: nowIso()
    };
    db.prepare(`
      INSERT INTO user_alert_settings (tenant_id, user_id, enabled, tags_json, severities_json, channel_ids_json, recipients_json, updated_at)
      VALUES (@tenantId, @userId, @enabled, @tagsJson, @severitiesJson, @channelIdsJson, @recipientsJson, @updatedAt)
      ON CONFLICT(tenant_id, user_id) DO UPDATE SET enabled=@enabled, tags_json=@tagsJson, severities_json=@severitiesJson,
        channel_ids_json=@channelIdsJson, recipients_json=@recipientsJson, updated_at=@updatedAt
    `).run({
      ...next,
      enabled: next.enabled ? 1 : 0,
      tagsJson: JSON.stringify(next.tags),
      severitiesJson: JSON.stringify(next.severities),
      channelIdsJson: JSON.stringify(next.channelIds),
      recipientsJson: JSON.stringify(next.recipients)
    });
    return next;
  },
  deleteForUser(tenantId: string, userId: string) {
    db.prepare("DELETE FROM user_alert_settings WHERE tenant_id = ? AND user_id = ?").run(tenantId, userId);
  }
};

export const sessions = {
  create(userId: string, token: string, csrfToken: string, impersonatorUserId?: string | null) {
    db.prepare(`
      INSERT INTO sessions (token, user_id, csrf_token, expires_at, created_at, impersonator_user_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      token,
      userId,
      csrfToken,
      addSecondsIso(60 * 60 * 24 * 14),
      nowIso(),
      impersonatorUserId ?? null
    );
  },
  find(token: string) {
    return db.prepare("SELECT * FROM sessions WHERE token = ? AND expires_at > ?").get(token, nowIso()) as any;
  },
  delete(token: string) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
  }
};

export const apiTokens = {
  list(): ApiToken[] {
    return db.prepare("SELECT * FROM api_tokens ORDER BY created_at DESC").all().map(rowToApiToken);
  },
  findByHash(tokenHash: string): ApiToken | null {
    const row = db.prepare("SELECT * FROM api_tokens WHERE token_hash = ?").get(tokenHash);
    return row ? rowToApiToken(row) : null;
  },
  create(name: string, tokenHash: string, scopes: string[], userId: string): ApiToken {
    const token = { id: id(), name, tokenHash, scopes, userId, createdAt: nowIso(), lastUsedAt: null };
    db.prepare("INSERT INTO api_tokens VALUES (?, ?, ?, ?, ?, ?, ?)").run(token.id, token.name, token.tokenHash, JSON.stringify(token.scopes), token.userId, token.createdAt, token.lastUsedAt);
    return token;
  },
  markUsed(tokenId: string) {
    db.prepare("UPDATE api_tokens SET last_used_at = ? WHERE id = ?").run(nowIso(), tokenId);
  },
  delete(tokenId: string) {
    db.prepare("DELETE FROM api_tokens WHERE id = ?").run(tokenId);
  }
};

export const monitors = {
  list(tenantId = DEFAULT_TENANT_ID): Monitor[] {
    return db.prepare("SELECT * FROM monitors WHERE tenant_id = ? ORDER BY name").all(tenantId).map(rowToMonitor);
  },
  count(tenantId: string): number {
    const row = db.prepare("SELECT COUNT(*) AS count FROM monitors WHERE tenant_id = ?").get(tenantId) as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  },
  /** Monitors of every organization that has not been deleted, for the operator's metrics. */
  listAll(): Monitor[] {
    return db.prepare(`
      SELECT m.* FROM monitors m
      JOIN tenants t ON t.id = m.tenant_id
      WHERE t.deleted_at IS NULL
      ORDER BY t.name, m.name
    `).all().map(rowToMonitor);
  },
  due(limit: number): Monitor[] {
    return db
      .prepare("SELECT * FROM monitors WHERE enabled = 1 AND (next_check_at IS NULL OR next_check_at <= ?) LIMIT ?")
      .all(nowIso(), limit)
      .map(rowToMonitor);
  },
  get(monitorId: string, tenantId?: string): Monitor | null {
    const row = tenantId ? db.prepare("SELECT * FROM monitors WHERE id = ? AND tenant_id = ?").get(monitorId, tenantId) : db.prepare("SELECT * FROM monitors WHERE id = ?").get(monitorId);
    return row ? rowToMonitor(row) : null;
  },
  create(input: Omit<Monitor, "id" | "lastStatus" | "createdAt" | "updatedAt" | "nextCheckAt">): Monitor {
    const createdAt = nowIso();
    const monitor: Monitor = { ...input, tenantId: input.tenantId ?? DEFAULT_TENANT_ID, id: id(), lastStatus: input.enabled ? "UNKNOWN" : "PAUSED", nextCheckAt: null, createdAt, updatedAt: createdAt };
    db.prepare(`
      INSERT INTO monitors (id, tenant_id, name, host, port, type, enabled, interval_seconds,
      timeout_seconds, warning_days, critical_days, grace_period_seconds, sni_enabled, sni_host, validate_certificate,
      allow_self_signed, tags_json, notes, owner, channel_ids_json, notification_recipients_json,
      config_json, maintenance_windows, last_status, next_check_at, created_at, updated_at)
      VALUES (@id, @tenantId, @name, @host, @port, @type, @enabled, @intervalSeconds,
      @timeoutSeconds, @warningDays, @criticalDays, @gracePeriodSeconds, @sniEnabled, @sniHost, @validateCertificate,
      @allowSelfSigned, @tagsJson, @notes, @owner, @channelIdsJson, @notificationRecipientsJson,
      @configJson, @maintenanceWindows, @lastStatus, @nextCheckAt, @createdAt, @updatedAt)
    `).run(serializeMonitor(monitor));
    return monitor;
  },
  update(monitor: Monitor): Monitor {
    const lastStatus: MonitorStatus = monitor.enabled ? (monitor.lastStatus === "PAUSED" ? "UNKNOWN" : monitor.lastStatus) : "PAUSED";
    const updated = { ...monitor, updatedAt: nowIso(), lastStatus };
    db.prepare(`
      UPDATE monitors SET name=@name, host=@host, port=@port, type=@type, enabled=@enabled,
      interval_seconds=@intervalSeconds, timeout_seconds=@timeoutSeconds, warning_days=@warningDays,
      critical_days=@criticalDays, grace_period_seconds=@gracePeriodSeconds, sni_enabled=@sniEnabled, sni_host=@sniHost,
      validate_certificate=@validateCertificate, allow_self_signed=@allowSelfSigned,
      tags_json=@tagsJson, notes=@notes, owner=@owner, channel_ids_json=@channelIdsJson,
      notification_recipients_json=@notificationRecipientsJson,
      config_json=@configJson,
      maintenance_windows=@maintenanceWindows, last_status=@lastStatus, next_check_at=@nextCheckAt,
      updated_at=@updatedAt WHERE id=@id
    `).run(serializeMonitor(updated));
    return updated;
  },
  delete(monitorId: string, tenantId?: string) {
    if (tenantId && !this.get(monitorId, tenantId)) return;
    db.prepare("DELETE FROM check_results WHERE monitor_id = ?").run(monitorId);
    db.prepare("DELETE FROM alert_history WHERE monitor_id = ?").run(monitorId);
    db.prepare("DELETE FROM monitors WHERE id = ?").run(monitorId);
  },
  markChecked(monitor: Monitor, result: CheckResult) {
    db.prepare("UPDATE monitors SET last_status = ?, next_check_at = ?, updated_at = ? WHERE id = ?").run(
      result.status,
      addSecondsIso(monitor.intervalSeconds),
      nowIso(),
      monitor.id
    );
  }
};

export const results = {
  list(monitorId: string, limit = 100): CheckResult[] {
    return db
      .prepare("SELECT * FROM check_results WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT ?")
      .all(monitorId, limit)
      .map(rowToResult);
  },
  /** The newest result per monitor; with a tenant only for that organization's monitors. */
  latestByMonitor(tenantId?: string): Record<string, CheckResult> {
    const rows = tenantId
      ? db.prepare(`
        SELECT cr.* FROM check_results cr
        JOIN (
          SELECT r.monitor_id, MAX(r.checked_at) checked_at FROM check_results r
          JOIN monitors m ON m.id = r.monitor_id
          WHERE m.tenant_id = ?
          GROUP BY r.monitor_id
        ) latest
        ON cr.monitor_id = latest.monitor_id AND cr.checked_at = latest.checked_at
      `).all(tenantId)
      : db.prepare(`
        SELECT cr.* FROM check_results cr
        JOIN (SELECT monitor_id, MAX(checked_at) checked_at FROM check_results GROUP BY monitor_id) latest
        ON cr.monitor_id = latest.monitor_id AND cr.checked_at = latest.checked_at
      `).all();
    return Object.fromEntries(rows.map((row: any) => [row.monitor_id, rowToResult(row)]));
  },
  /**
   * The newest SSL Labs assessment of a host among the organization's monitors.
   * Each organization assesses with its own SSL Labs account and settings, so
   * an assessment is reused only within the organization that ran it.
   */
  latestSslLabsForHost(host: string, tenantId: string): CheckResult | undefined {
    const row = db.prepare(`
      SELECT cr.* FROM check_results cr
      JOIN monitors m ON m.id = cr.monitor_id
      WHERE lower(m.host) = lower(?) AND m.tenant_id = ? AND cr.ssl_labs_checked_at IS NOT NULL
      ORDER BY cr.ssl_labs_checked_at DESC
      LIMIT 1
    `).get(host, tenantId);
    return row ? rowToResult(row) : undefined;
  },
  insert(result: CheckResult) {
    db.prepare(`
      INSERT INTO check_results (id, monitor_id, status, severity, message, checked_at,
      duration_ms, days_remaining, valid_from, valid_until, common_name, subject_alt_names_json,
      issuer, serial_number, fingerprint_sha256, tls_version, cipher_suite, tls_grade, tls_score,
      tls_grade_reasons_json, tls_supported_versions_json, ssl_labs_grade, ssl_labs_score, ssl_labs_status, ssl_labs_url,
      ssl_labs_checked_at, ssl_labs_findings_json, dns_json, flapping, chain_json, problems_json, raw_error)
      VALUES (@id, @monitorId, @status, @severity, @message, @checkedAt, @durationMs,
      @daysRemaining, @validFrom, @validUntil, @commonName, @subjectAltNamesJson, @issuer,
      @serialNumber, @fingerprintSha256, @tlsVersion, @cipherSuite, @tlsGrade, @tlsScore,
      @tlsGradeReasonsJson, @tlsSupportedVersionsJson, @sslLabsGrade, @sslLabsScore, @sslLabsStatus, @sslLabsUrl,
      @sslLabsCheckedAt, @sslLabsFindingsJson, @dnsJson, @flapping, @chainJson, @problemsJson, @rawError)
    `).run({
      ...result,
      flapping: result.flapping ? 1 : 0,
      subjectAltNamesJson: JSON.stringify(result.subjectAltNames),
      tlsGradeReasonsJson: JSON.stringify(result.tlsGradeReasons ?? []),
      tlsSupportedVersionsJson: JSON.stringify(result.tlsSupportedVersions ?? []),
      sslLabsFindingsJson: JSON.stringify(result.sslLabsFindings ?? []),
      dnsJson: result.dns ? JSON.stringify(result.dns) : null,
      chainJson: JSON.stringify(result.chain),
      problemsJson: JSON.stringify(result.problems)
    });
  },
  consecutiveFailureStartedAt(monitorId: string): string | null {
    const rows = db.prepare("SELECT status, checked_at FROM check_results WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 500").all(monitorId) as Array<{ status: string; checked_at: string }>;
    const failures = [];
    for (const row of rows) {
      if (row.status === "OK") break;
      failures.push(row);
    }
    return failures.at(-1)?.checked_at ?? null;
  },
  listRecent(monitorId: string, limit = 10): CheckResult[] {
    return db.prepare("SELECT * FROM check_results WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT ?").all(monitorId, limit).map(rowToResult);
  },
  prune(days: number) {
    db.prepare("DELETE FROM check_results WHERE checked_at < ?").run(new Date(Date.now() - days * 86_400_000).toISOString());
  }
};

/* Incidents, alert history and deliveries carry no organization of their own;
   they belong to the organization of their monitor, so every read and write
   that comes from a request joins the monitor and checks its tenant. */
export const incidents = {
  list(tenantId: string, limit = 100): Incident[] {
    return db.prepare(`
      SELECT i.* FROM incidents i
      JOIN monitors m ON m.id = i.monitor_id
      WHERE m.tenant_id = ?
      ORDER BY i.started_at DESC LIMIT ?
    `).all(tenantId, limit).map(rowToIncident);
  },
  listForMonitor(monitorId: string, limit = 50): Incident[] {
    return db.prepare("SELECT * FROM incidents WHERE monitor_id = ? ORDER BY started_at DESC LIMIT ?").all(monitorId, limit).map(rowToIncident);
  },
  openForMonitor(monitorId: string): Incident | null {
    const row = db.prepare("SELECT * FROM incidents WHERE monitor_id = ? AND resolved_at IS NULL ORDER BY started_at DESC LIMIT 1").get(monitorId);
    return row ? rowToIncident(row) : null;
  },
  sync(monitor: Monitor, result: CheckResult): Incident | null {
    const open = this.openForMonitor(monitor.id);
    if (result.status === "OK") {
      if (open) db.prepare("UPDATE incidents SET resolved_at = ? WHERE id = ?").run(result.checkedAt, open.id);
      return open ? { ...open, resolvedAt: result.checkedAt } : null;
    }
    if (open) {
      db.prepare("UPDATE incidents SET status = ?, severity = ?, message = ? WHERE id = ?").run(result.status, result.severity, result.message, open.id);
      return { ...open, status: result.status, severity: result.severity, message: result.message };
    }
    const incident = { id: id(), monitorId: monitor.id, status: result.status, severity: result.severity, message: result.message, startedAt: result.checkedAt, resolvedAt: null, acknowledgedAt: null, acknowledgedBy: null, assignee: null, notes: [] };
    db.prepare("INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(incident.id, incident.monitorId, incident.status, incident.severity, incident.message, incident.startedAt, incident.resolvedAt, incident.acknowledgedAt, incident.acknowledgedBy, incident.assignee, JSON.stringify(incident.notes));
    return incident;
  },
  /** Null when the incident does not exist or belongs to a monitor of another organization. */
  acknowledge(incidentId: string, tenantId: string, userEmail: string, assignee?: string | null, comment?: string | null): Incident | null {
    if (!this.get(incidentId, tenantId)) return null;
    db.prepare("UPDATE incidents SET acknowledged_at = ?, acknowledged_by = ?, assignee = COALESCE(?, assignee) WHERE id = ?").run(nowIso(), userEmail, assignee ?? null, incidentId);
    return comment?.trim() ? this.addNote(incidentId, tenantId, userEmail, comment.trim()) : this.get(incidentId, tenantId);
  },
  get(incidentId: string, tenantId: string): Incident | null {
    const row = db.prepare(`
      SELECT i.* FROM incidents i
      JOIN monitors m ON m.id = i.monitor_id
      WHERE i.id = ? AND m.tenant_id = ?
    `).get(incidentId, tenantId);
    return row ? rowToIncident(row) : null;
  },
  /** Null when the incident does not exist or belongs to a monitor of another organization. */
  addNote(incidentId: string, tenantId: string, userEmail: string, text: string): Incident | null {
    const current = this.get(incidentId, tenantId);
    if (!current) return null;
    const note: IncidentNote = { id: id(), author: userEmail, text, createdAt: nowIso() };
    const notes = [...current.notes, note];
    db.prepare("UPDATE incidents SET notes_json = ? WHERE id = ?").run(JSON.stringify(notes), incidentId);
    return { ...current, notes };
  }
};

export const deliveries = {
  list(tenantId: string, limit = 100): NotificationDelivery[] {
    return db.prepare(`
      SELECT d.* FROM notification_deliveries d
      JOIN monitors m ON m.id = d.monitor_id
      WHERE m.tenant_id = ?
      ORDER BY d.sent_at DESC LIMIT ?
    `).all(tenantId, limit).map(rowToDelivery);
  },
  record(input: Omit<NotificationDelivery, "id" | "sentAt">) {
    const delivery = { ...input, id: id(), sentAt: nowIso() };
    db.prepare("INSERT INTO notification_deliveries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
      delivery.id,
      delivery.monitorId,
      delivery.channelId ?? null,
      delivery.channelName,
      delivery.provider,
      delivery.target,
      delivery.severity,
      delivery.status,
      delivery.deliveryStatus,
      delivery.message,
      delivery.error ?? null,
      delivery.sentAt
    );
  },
  prune(days: number) {
    db.prepare("DELETE FROM notification_deliveries WHERE sent_at < ?").run(new Date(Date.now() - days * 86_400_000).toISOString());
  }
};

export const subscriptions = {
  list(tenantId: string): StatusSubscription[] {
    return db.prepare("SELECT * FROM status_subscriptions WHERE tenant_id = ? ORDER BY created_at DESC").all(tenantId).map(rowToSubscription);
  },
  create(input: { tenantId: string; pageSlug: string | null; tags: string[]; type: "email" | "webhook"; target: string; enabled?: boolean }): StatusSubscription {
    const subscription: StatusSubscription = { id: id(), tenantId: input.tenantId, pageSlug: input.pageSlug, tags: input.tags, type: input.type, target: input.target, enabled: input.enabled ?? false, createdAt: nowIso() };
    db.prepare(`
      INSERT INTO status_subscriptions (id, tenant_id, page_slug, tags_json, type, target, enabled, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(subscription.id, subscription.tenantId, subscription.pageSlug, JSON.stringify(subscription.tags), subscription.type, subscription.target, subscription.enabled ? 1 : 0, subscription.createdAt);
    return subscription;
  },
  // The confirmation link carries the random id and reaches only the subscriber.
  confirm(subscriptionId: string): StatusSubscription | null {
    db.prepare("UPDATE status_subscriptions SET enabled = 1 WHERE id = ?").run(subscriptionId);
    const row = db.prepare("SELECT * FROM status_subscriptions WHERE id = ?").get(subscriptionId);
    return row ? rowToSubscription(row) : null;
  },
  /** Deletes within one organization and reports whether a subscription was removed. */
  delete(subscriptionId: string, tenantId: string): boolean {
    return db.prepare("DELETE FROM status_subscriptions WHERE id = ? AND tenant_id = ?").run(subscriptionId, tenantId).changes > 0;
  }
};

export const channels = {
  list(tenantId = DEFAULT_TENANT_ID): NotificationChannel[] {
    return db.prepare("SELECT * FROM notification_channels WHERE tenant_id = ? ORDER BY name").all(tenantId).map(rowToChannel);
  },
  get(channelId: string, tenantId?: string): NotificationChannel | null {
    const row = tenantId ? db.prepare("SELECT * FROM notification_channels WHERE id = ? AND tenant_id = ?").get(channelId, tenantId) : db.prepare("SELECT * FROM notification_channels WHERE id = ?").get(channelId);
    return row ? rowToChannel(row) : null;
  },
  /**
   * Creates the channel or updates it within its own organization. An id that
   * belongs to a channel of another organization changes nothing; the result
   * says whether the channel was written.
   */
  upsert(channel: NotificationChannel): boolean {
    return db.prepare(`
      INSERT INTO notification_channels (id, tenant_id, name, type, enabled, config_json, created_at, updated_at)
      VALUES (@id, @tenantId, @name, @type, @enabled, @configJson, @createdAt, @updatedAt)
      ON CONFLICT(id) DO UPDATE SET name=@name, type=@type, enabled=@enabled, config_json=@configJson, updated_at=@updatedAt
      WHERE notification_channels.tenant_id = excluded.tenant_id
    `).run({ ...channel, tenantId: channel.tenantId ?? DEFAULT_TENANT_ID, configJson: JSON.stringify(encryptConfigSecrets(channel.config ?? {})) }).changes > 0;
  },
  delete(channelId: string, tenantId?: string) {
    if (tenantId) db.prepare("DELETE FROM notification_channels WHERE id = ? AND tenant_id = ?").run(channelId, tenantId);
    else db.prepare("DELETE FROM notification_channels WHERE id = ?").run(channelId);
  }
};

export const alerts = {
  shouldSend(monitorId: string, status: string, fingerprint: string, resendAfterHours = 24) {
    const row = db.prepare("SELECT * FROM alert_history WHERE monitor_id=? ORDER BY sent_at DESC LIMIT 1").get(monitorId) as any;
    if (!row) return true;
    if (row.status !== status || row.fingerprint !== fingerprint) return true;
    return Date.now() - new Date(row.sent_at).getTime() > resendAfterHours * 3_600_000;
  },
  record(monitorId: string, channelId: string | null, severity: string, status: string, fingerprint: string, message: string) {
    db.prepare("INSERT INTO alert_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(
      id(),
      monitorId,
      channelId,
      severity,
      status,
      fingerprint,
      message,
      nowIso()
    );
  },
  list(tenantId: string, limit = 100) {
    return db.prepare(`
      SELECT a.* FROM alert_history a
      JOIN monitors m ON m.id = a.monitor_id
      WHERE m.tenant_id = ?
      ORDER BY a.sent_at DESC LIMIT ?
    `).all(tenantId, limit);
  },
  prune(days: number) {
    db.prepare("DELETE FROM alert_history WHERE sent_at < ?").run(new Date(Date.now() - days * 86_400_000).toISOString());
  }
};

export const appSettings = {
  platform(): PlatformSettings {
    return this.get("platform", { publicRegistrationEnabled: true });
  },
  alerting(tenantId?: string): AlertingSettings {
    return this.get("alerting", {
      resendAfterHours: 24,
      recoveryEnabled: true,
      certificateChangeAlerts: true,
      dnsChangeAlerts: false,
      tlsDeteriorationAlerts: true,
      tlsDeteriorationThreshold: 5,
      quietHoursEnabled: false,
      quietStart: "22:00",
      quietEnd: "07:00",
      quietSuppressCritical: false,
      flappingThreshold: 4
    }, tenantId);
  },
  smtp(tenantId?: string): SmtpSettings {
    return this.get("smtp", {
      host: "",
      port: 587,
      username: "",
      password: "",
      from: "",
      secure: false,
      starttls: true
    }, tenantId);
  },
  retention(tenantId?: string): RetentionSettings {
    return this.get("retention", { checkResultsDays: 365, alertHistoryDays: 365 }, tenantId);
  },
  notificationRoutes(tenantId?: string): NotificationRoute[] {
    return this.get("notificationRoutes", [], tenantId);
  },
  ctWatch(tenantId?: string): CtWatchSettings {
    return this.get("ctWatch", { enabled: false, domains: [], lastSeen: {} }, tenantId);
  },
  maintenance(tenantId?: string): MaintenanceSettings {
    return this.get("maintenance", { windows: [] }, tenantId);
  },
  tlsPolicy(tenantId?: string): TlsPolicySettings {
    return this.get("tlsPolicy", { profile: "modern", minimumTlsVersion: "TLSv1.2", weakCipherPenalty: 40, requireSan: true, intensiveScan: true }, tenantId);
  },
  sslLabs(tenantId?: string): SslLabsSettings {
    return this.get("sslLabs", { enabled: false, registeredEmail: "", intervalHours: 24, maxAgeHours: 24, timeoutSeconds: 90, startNewScans: false, publishResults: false }, tenantId);
  },
  statusPages(tenantId?: string): StatusPageSettings {
    return this.get("statusPages", { pages: [] }, tenantId);
  },
  discovery(tenantId?: string): DiscoverySettings {
    return this.get("discovery", { enabled: false, intervalHours: 24, domains: [], suggestions: [], lastRunAt: null }, tenantId);
  },
  backups(tenantId?: string): BackupSettings {
    return this.get("backups", { enabled: false, intervalHours: 24, keep: 7, lastRunAt: null }, tenantId);
  },
  get<T>(key: string, fallback: T, tenantId?: string): T {
    const row = db.prepare("SELECT value_json FROM settings WHERE key = ?").get(settingKey(key, tenantId)) as { value_json?: string } | undefined;
    return parseSetting(row?.value_json, fallback);
  },
  set<T>(key: string, value: T, tenantId?: string) {
    const stored = isPlainSettingsObject(value) ? encryptConfigSecrets(value as Record<string, unknown>) : value;
    db.prepare("INSERT INTO settings VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json").run(
      settingKey(key, tenantId),
      JSON.stringify(stored)
    );
  },
  delete(key: string, tenantId?: string) {
    db.prepare("DELETE FROM settings WHERE key = ?").run(settingKey(key, tenantId));
  },
  /** One setting of every organization that has stored it, read in a single query. */
  everyTenant<T>(key: string, fallback: T): Array<{ tenantId: string; value: T }> {
    const rows = db.prepare("SELECT key, value_json FROM settings WHERE key = ? OR key LIKE ?").all(key, `tenant:%:${key}`) as Array<{ key: string; value_json?: string }>;
    return rows.flatMap((row) => {
      const tenantId = row.key === key ? DEFAULT_TENANT_ID : row.key.slice("tenant:".length, -(key.length + 1));
      return tenantId ? [{ tenantId, value: parseSetting(row.value_json, fallback) }] : [];
    });
  }
};

const parseSetting = <T>(valueJson: string | undefined, fallback: T): T => {
  if (!valueJson) return fallback;
  try {
    const parsed = JSON.parse(valueJson);
    const value = isPlainSettingsObject(parsed) ? decryptConfigSecrets(parsed) : parsed;
    if (Array.isArray(fallback)) return (Array.isArray(value) ? value : fallback) as T;
    return { ...fallback, ...value };
  } catch {
    return fallback;
  }
};

const serializeMonitor = (monitor: Monitor) => ({
  ...monitor,
  tenantId: monitor.tenantId ?? DEFAULT_TENANT_ID,
  enabled: monitor.enabled ? 1 : 0,
  sniEnabled: monitor.sniEnabled ? 1 : 0,
  validateCertificate: monitor.validateCertificate ? 1 : 0,
  allowSelfSigned: monitor.allowSelfSigned ? 1 : 0,
  tagsJson: JSON.stringify(monitor.tags),
  channelIdsJson: JSON.stringify(monitor.notificationChannelIds),
  notificationRecipientsJson: JSON.stringify(monitor.notificationRecipients ?? {}),
  configJson: JSON.stringify(encryptConfigSecrets(monitor.config ?? {}))
});

const isPlainSettingsObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const settingKey = (key: string, tenantId?: string) => tenantId && tenantId !== DEFAULT_TENANT_ID ? `tenant:${tenantId}:${key}` : key;

const defaultUserAlerts = (tenantId: string, userId: string): UserAlertSettings => ({
  tenantId,
  userId,
  enabled: false,
  tags: [],
  severities: ["warning", "recovery"],
  channelIds: [],
  recipients: {},
  updatedAt: nowIso()
});

const slugify = (value: string) =>
  value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "organization";

const uniqueSlug = (base: string) => {
  let slug = base;
  let suffix = 2;
  while (db.prepare("SELECT id FROM tenants WHERE slug = ?").get(slug)) {
    slug = `${base}-${suffix}`;
    suffix += 1;
  }
  return slug;
};

const uniqueTeamSlug = (tenantId: string, base: string, ignoreTeamId?: string) => {
  let slug = base;
  let suffix = 2;
  while (db.prepare("SELECT id FROM teams WHERE tenant_id = ? AND slug = ? AND id <> COALESCE(?, '')").get(tenantId, slug, ignoreTeamId ?? "")) {
    slug = `${base}-${suffix}`;
    suffix += 1;
  }
  return slug;
};

const activeTenantMember = (tenantId: string, userId: string) =>
  Boolean(db.prepare("SELECT user_id FROM tenant_memberships WHERE tenant_id = ? AND user_id = ? AND status = 'active'").get(tenantId, userId));

const hashInviteToken = (token: string) =>
  createHash("sha256").update(token).digest("hex");

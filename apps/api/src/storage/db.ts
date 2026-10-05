import fs from "node:fs";
import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import { env } from "../config/env.js";
import type { ApiToken, AuditLogEntry, CheckResult, Incident, Monitor, NotificationChannel, NotificationDelivery, StatusSubscription, Team, TeamMembership, Tenant, TenantInvite, TenantMembership, User, UserAlertSettings } from "../types.js";
import { DEFAULT_TENANT_ID } from "../types.js";
import { decryptConfigSecrets } from "../utils/secrets.js";
import { assertWritableDataDirectory } from "./dataDirectory.js";

assertWritableDataDirectory(env.databasePath);
const sqlite = new Database(env.databasePath);
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("synchronous = NORMAL");
sqlite.pragma("busy_timeout = 5000");

const statements = new Map<string, Database.Statement>();
const prepared = (sql: string) => {
  let statement = statements.get(sql);
  if (!statement) {
    statement = sqlite.prepare(sql);
    statements.set(sql, statement);
  }
  return statement;
};

export const db = {
  exec(sql: string) {
    sqlite.exec(sql);
  },
  prepare(sql: string) {
    return new StatementWrapper(sql);
  },
  /** Checkpoints the WAL into the main database file, e.g. before copies or shutdown. */
  flush() {
    try {
      sqlite.pragma("wal_checkpoint(TRUNCATE)");
    } catch {
      // Best effort: a busy checkpoint retries on the next flush.
    }
  }
};

class StatementWrapper {
  constructor(private readonly sql: string) {}

  run(...params: unknown[]) {
    prepared(this.sql).run(...bindParams(this.sql, params));
  }

  get(...params: unknown[]) {
    return prepared(this.sql).get(...bindParams(this.sql, params)) as Record<string, unknown> | undefined;
  }

  all(...params: unknown[]) {
    return prepared(this.sql).all(...bindParams(this.sql, params)) as Record<string, unknown>[];
  }
}

// better-sqlite3 requires the bound object to contain exactly the named
// parameters used in the SQL. Callers often spread wider objects (extra keys)
// or omit optional fields (missing keys), which sql.js tolerated, so the
// object is trimmed to the parameter names parsed from the statement and
// missing values become NULL.
const namedParamCache = new Map<string, string[]>();
const namedParams = (sql: string) => {
  let names = namedParamCache.get(sql);
  if (!names) {
    const withoutLiterals = sql.replace(/'(?:[^']|'')*'/g, "");
    names = [...new Set([...withoutLiterals.matchAll(/[@:$]([a-zA-Z_][a-zA-Z0-9_]*)/g)].map((match) => match[1]))];
    namedParamCache.set(sql, names);
  }
  return names;
};

const bindParams = (sql: string, params: unknown[]) => {
  if (params.length === 1 && isPlainObject(params[0])) {
    const source = params[0];
    return [Object.fromEntries(namedParams(sql).map((name) => [name, normalizeValue(source[name])]))];
  }
  return params.map(normalizeValue);
};

const normalizeValue = (value: unknown) => {
  if (value === undefined) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (typeof value === "string" || typeof value === "number" || typeof value === "bigint" || value === null || Buffer.isBuffer(value)) return value;
  return JSON.stringify(value);
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === "object" && !Array.isArray(value) && !Buffer.isBuffer(value));

export const migrate = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT NOT NULL,
      impersonator_user_id TEXT,
      mfa_secret TEXT,
      mfa_enabled INTEGER NOT NULL DEFAULT 0,
      mfa_backup_codes_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf_token TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS api_tokens (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      scopes_json TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free',
      status TEXT NOT NULL DEFAULT 'active',
      monitor_limit INTEGER NOT NULL DEFAULT 50,
      user_limit INTEGER NOT NULL DEFAULT 5,
      team_limit INTEGER NOT NULL DEFAULT 10,
      settings_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT '',
      deleted_at TEXT
    );
    CREATE TABLE IF NOT EXISTS tenant_memberships (
      id TEXT,
      tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT '',
      PRIMARY KEY (tenant_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS tenant_invites (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      role TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      token_hash TEXT,
      team_id TEXT,
      team_role TEXT,
      invited_by_user_id TEXT,
      accepted_at TEXT,
      revoked_at TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      visibility TEXT NOT NULL DEFAULT 'tenant_visible',
      status TEXT NOT NULL DEFAULT 'active',
      settings_json TEXT NOT NULL DEFAULT '{}',
      created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      deleted_at TEXT,
      UNIQUE (tenant_id, slug)
    );
    CREATE TABLE IF NOT EXISTS team_memberships (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
      team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE (team_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS user_alert_settings (
      tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      enabled INTEGER NOT NULL DEFAULT 0,
      tags_json TEXT NOT NULL DEFAULT '[]',
      severities_json TEXT NOT NULL DEFAULT '[]',
      channel_ids_json TEXT NOT NULL DEFAULT '[]',
      recipients_json TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT NOT NULL,
      PRIMARY KEY (tenant_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS monitors (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL DEFAULT '${DEFAULT_TENANT_ID}',
      name TEXT NOT NULL,
      host TEXT NOT NULL,
      port INTEGER NOT NULL,
      type TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      interval_seconds INTEGER NOT NULL,
      timeout_seconds INTEGER NOT NULL,
      warning_days INTEGER NOT NULL,
      critical_days INTEGER NOT NULL,
      grace_period_seconds INTEGER NOT NULL DEFAULT 0,
      sni_enabled INTEGER NOT NULL,
      sni_host TEXT,
      validate_certificate INTEGER NOT NULL,
      allow_self_signed INTEGER NOT NULL,
      tags_json TEXT NOT NULL,
      notes TEXT,
      owner TEXT,
      channel_ids_json TEXT NOT NULL,
      notification_recipients_json TEXT NOT NULL DEFAULT '{}',
      config_json TEXT NOT NULL DEFAULT '{}',
      maintenance_windows TEXT,
      last_status TEXT NOT NULL,
      next_check_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS check_results (
      id TEXT PRIMARY KEY,
      monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
      status TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      duration_ms INTEGER NOT NULL,
      days_remaining INTEGER,
      valid_from TEXT,
      valid_until TEXT,
      common_name TEXT,
      subject_alt_names_json TEXT NOT NULL,
      issuer TEXT,
      serial_number TEXT,
      fingerprint_sha256 TEXT,
      tls_version TEXT,
      cipher_suite TEXT,
      tls_grade TEXT,
      tls_score INTEGER,
      tls_grade_reasons_json TEXT NOT NULL DEFAULT '[]',
      tls_supported_versions_json TEXT NOT NULL DEFAULT '[]',
      ssl_labs_grade TEXT,
      ssl_labs_score INTEGER,
      ssl_labs_status TEXT,
      ssl_labs_url TEXT,
      ssl_labs_checked_at TEXT,
      ssl_labs_findings_json TEXT NOT NULL DEFAULT '[]',
      dns_json TEXT,
      flapping INTEGER NOT NULL DEFAULT 0,
      chain_json TEXT NOT NULL,
      problems_json TEXT NOT NULL,
      raw_error TEXT
    );
    CREATE TABLE IF NOT EXISTS notification_channels (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL DEFAULT '${DEFAULT_TENANT_ID}',
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      enabled INTEGER NOT NULL,
      config_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alert_history (
      id TEXT PRIMARY KEY,
      monitor_id TEXT NOT NULL,
      channel_id TEXT,
      severity TEXT NOT NULL,
      status TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      message TEXT NOT NULL,
      sent_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notification_deliveries (
      id TEXT PRIMARY KEY,
      monitor_id TEXT NOT NULL,
      channel_id TEXT,
      channel_name TEXT NOT NULL,
      provider TEXT NOT NULL,
      target TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL,
      delivery_status TEXT NOT NULL,
      message TEXT NOT NULL,
      error TEXT,
      sent_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      monitor_id TEXT NOT NULL,
      status TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      started_at TEXT NOT NULL,
      resolved_at TEXT,
      acknowledged_at TEXT,
      acknowledged_by TEXT,
      assignee TEXT,
      notes_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS status_subscriptions (
      id TEXT PRIMARY KEY,
      tags_json TEXT NOT NULL,
      type TEXT NOT NULL,
      target TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      tenant_id TEXT,
      team_id TEXT,
      actor_user_id TEXT,
      target_user_id TEXT,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      details_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
  addColumns([
    "ALTER TABLE tenants ADD COLUMN team_limit INTEGER NOT NULL DEFAULT 10;",
    "ALTER TABLE tenants ADD COLUMN settings_json TEXT NOT NULL DEFAULT '{}';",
    "ALTER TABLE tenants ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE tenants ADD COLUMN deleted_at TEXT;",
    "ALTER TABLE tenant_memberships ADD COLUMN id TEXT;",
    "ALTER TABLE tenant_memberships ADD COLUMN status TEXT NOT NULL DEFAULT 'active';",
    "ALTER TABLE tenant_memberships ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE tenant_invites ADD COLUMN token_hash TEXT;",
    "ALTER TABLE tenant_invites ADD COLUMN team_id TEXT;",
    "ALTER TABLE tenant_invites ADD COLUMN team_role TEXT;",
    "ALTER TABLE tenant_invites ADD COLUMN revoked_at TEXT;",
    "ALTER TABLE tenant_invites ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE audit_log ADD COLUMN tenant_id TEXT;",
    "ALTER TABLE audit_log ADD COLUMN team_id TEXT;",
    "ALTER TABLE audit_log ADD COLUMN target_user_id TEXT;",
    "ALTER TABLE audit_log ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}';",
    "ALTER TABLE users ADD COLUMN mfa_secret TEXT;",
    "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;",
    "ALTER TABLE users ADD COLUMN mfa_backup_codes_json TEXT NOT NULL DEFAULT '[]';"
  ]);
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_tenant_memberships_tenant ON tenant_memberships(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_tenant_memberships_user ON tenant_memberships(user_id);
    CREATE INDEX IF NOT EXISTS idx_tenant_memberships_role ON tenant_memberships(role);
    CREATE INDEX IF NOT EXISTS idx_tenant_memberships_status ON tenant_memberships(status);
    CREATE INDEX IF NOT EXISTS idx_teams_tenant ON teams(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_teams_slug ON teams(tenant_id, slug);
    CREATE INDEX IF NOT EXISTS idx_teams_status ON teams(status);
    CREATE INDEX IF NOT EXISTS idx_teams_visibility ON teams(visibility);
    CREATE INDEX IF NOT EXISTS idx_team_memberships_tenant ON team_memberships(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_team_memberships_team ON team_memberships(team_id);
    CREATE INDEX IF NOT EXISTS idx_team_memberships_user ON team_memberships(user_id);
    CREATE INDEX IF NOT EXISTS idx_team_memberships_role ON team_memberships(role);
    CREATE INDEX IF NOT EXISTS idx_team_memberships_status ON team_memberships(status);
    CREATE INDEX IF NOT EXISTS idx_monitors_due ON monitors(enabled, next_check_at);
    CREATE INDEX IF NOT EXISTS idx_check_results_monitor_checked_at ON check_results(monitor_id, checked_at);
    CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_created ON audit_log(tenant_id, created_at);
  `);
  try {
    db.exec("ALTER TABLE sessions ADD COLUMN impersonator_user_id TEXT;");
  } catch {
    // Existing databases already have the column.
  }
  db.prepare("UPDATE users SET role = 'super_admin' WHERE role = 'admin'").run();
  db.prepare(`
    INSERT OR IGNORE INTO tenants (id, name, slug, plan, status, monitor_limit, user_limit, team_limit, settings_json, created_at, updated_at, deleted_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, NULL)
  `).run(DEFAULT_TENANT_ID, "Default organization", "default", "team", "active", 1000, 100, 100, new Date().toISOString(), new Date().toISOString());
  db.prepare("UPDATE tenants SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = ''").run();
  db.prepare(`
    INSERT OR IGNORE INTO tenant_memberships (id, tenant_id, user_id, role, status, created_at, updated_at)
    SELECT lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)),2) || '-' || substr('89ab', abs(random()) % 4 + 1, 1) || substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6))),
      ?, id, CASE WHEN role IN ('admin', 'super_admin') THEN 'owner' ELSE 'viewer' END, 'active', ?, ?
    FROM users
  `).run(DEFAULT_TENANT_ID, new Date().toISOString(), new Date().toISOString());
  db.prepare("UPDATE tenant_memberships SET id = lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)),2) || '-' || substr('89ab', abs(random()) % 4 + 1, 1) || substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6))) WHERE id IS NULL OR id = ''").run();
  db.prepare("UPDATE tenant_memberships SET status = 'active' WHERE status IS NULL OR status = ''").run();
  db.prepare("UPDATE tenant_memberships SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = ''").run();
  db.prepare("UPDATE tenant_invites SET token_hash = token WHERE token_hash IS NULL OR token_hash = ''").run();
  db.prepare("UPDATE tenant_invites SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = ''").run();
  try {
    db.exec(`ALTER TABLE monitors ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '${DEFAULT_TENANT_ID}';`);
  } catch {
    // Existing databases already have the column.
  }
  try {
    db.exec(`ALTER TABLE notification_channels ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '${DEFAULT_TENANT_ID}';`);
  } catch {
    // Existing databases already have the column.
  }
  db.prepare("UPDATE monitors SET tenant_id = ? WHERE tenant_id IS NULL OR tenant_id = ''").run(DEFAULT_TENANT_ID);
  db.prepare("UPDATE notification_channels SET tenant_id = ? WHERE tenant_id IS NULL OR tenant_id = ''").run(DEFAULT_TENANT_ID);
  try {
    db.exec("ALTER TABLE monitors ADD COLUMN notification_recipients_json TEXT NOT NULL DEFAULT '{}';");
  } catch {
    // Existing databases already have the column.
  }
  try {
    db.exec("ALTER TABLE monitors ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}';");
  } catch {
    // Existing databases already have the column.
  }
  try {
    db.exec("ALTER TABLE monitors ADD COLUMN grace_period_seconds INTEGER NOT NULL DEFAULT 0;");
  } catch {
    // Existing databases already have the column.
  }
  for (const sql of [
    "ALTER TABLE check_results ADD COLUMN tls_grade TEXT;",
    "ALTER TABLE check_results ADD COLUMN tls_score INTEGER;",
    "ALTER TABLE check_results ADD COLUMN tls_grade_reasons_json TEXT NOT NULL DEFAULT '[]';",
    "ALTER TABLE check_results ADD COLUMN tls_supported_versions_json TEXT NOT NULL DEFAULT '[]';",
    "ALTER TABLE check_results ADD COLUMN ssl_labs_grade TEXT;",
    "ALTER TABLE check_results ADD COLUMN ssl_labs_score INTEGER;",
    "ALTER TABLE check_results ADD COLUMN ssl_labs_status TEXT;",
    "ALTER TABLE check_results ADD COLUMN ssl_labs_url TEXT;",
    "ALTER TABLE check_results ADD COLUMN ssl_labs_checked_at TEXT;",
    "ALTER TABLE check_results ADD COLUMN ssl_labs_findings_json TEXT NOT NULL DEFAULT '[]';",
    "ALTER TABLE check_results ADD COLUMN dns_json TEXT;",
    "ALTER TABLE check_results ADD COLUMN flapping INTEGER NOT NULL DEFAULT 0;"
  ]) {
    try {
      db.exec(sql);
    } catch {
      // Existing databases already have the column.
    }
  }
  for (const sql of [
    "ALTER TABLE incidents ADD COLUMN acknowledged_at TEXT;",
    "ALTER TABLE incidents ADD COLUMN acknowledged_by TEXT;",
    "ALTER TABLE incidents ADD COLUMN assignee TEXT;",
    "ALTER TABLE incidents ADD COLUMN notes_json TEXT NOT NULL DEFAULT '[]';"
  ]) {
    try {
      db.exec(sql);
    } catch {
      // Existing databases already have the column.
    }
  }
  ensureDefaultTeams();
  snapshotLastGoodDatabase();
};

// Keep a copy of the last database that contained at least one user next to
// the live file. A fresh or wiped database never overwrites the snapshot, so
// after an accidental wipe the previous state can be restored from
// `<databasePath>.boot-bak`.
const snapshotLastGoodDatabase = () => {
  try {
    const row = db.prepare("SELECT COUNT(*) AS count FROM users").get() as { count?: number } | undefined;
    if (Number(row?.count ?? 0) === 0) return;
    db.flush();
    const tmp = `${env.databasePath}.boot-bak.tmp`;
    fs.copyFileSync(env.databasePath, tmp);
    fs.renameSync(tmp, `${env.databasePath}.boot-bak`);
  } catch {
    // Snapshotting is best-effort and must never block startup.
  }
};

const addColumns = (statements: string[]) => {
  for (const sql of statements) {
    try {
      db.exec(sql);
    } catch {
      // Existing databases already have the column.
    }
  }
};

const ensureDefaultTeams = () => {
  const now = new Date().toISOString();
  const rows = db.prepare("SELECT id FROM tenants WHERE deleted_at IS NULL").all() as Array<{ id: string }>;
  for (const row of rows) {
    const existing = db.prepare("SELECT id FROM teams WHERE tenant_id = ? AND slug = 'general'").get(row.id) as { id?: string } | undefined;
    const teamId = existing?.id ?? randomUUID();
    if (!existing) {
      db.prepare(`
        INSERT INTO teams (id, tenant_id, name, slug, description, visibility, status, settings_json, created_by_user_id, created_at, updated_at, deleted_at)
        VALUES (?, ?, 'General', 'general', 'Default team for this organization.', 'tenant_visible', 'active', '{}', NULL, ?, ?, NULL)
      `).run(teamId, row.id, now, now);
    }
    db.prepare(`
      INSERT OR IGNORE INTO team_memberships (id, tenant_id, team_id, user_id, role, status, created_at, updated_at)
      SELECT lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)),2) || '-' || substr('89ab', abs(random()) % 4 + 1, 1) || substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6))),
        tenant_id, ?, user_id, CASE WHEN role IN ('owner', 'admin') THEN 'team_owner' ELSE 'team_member' END, 'active', ?, ?
      FROM tenant_memberships
      WHERE tenant_id = ? AND status = 'active'
    `).run(teamId, now, now, row.id);
  }
};

const parse = <T>(value: string | null | undefined, fallback: T): T => {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
};

export const rowToMonitor = (row: any): Monitor => ({
  id: row.id,
  tenantId: row.tenant_id ?? DEFAULT_TENANT_ID,
  name: row.name,
  host: row.host,
  port: row.port,
  type: row.type,
  enabled: Boolean(row.enabled),
  intervalSeconds: row.interval_seconds,
  timeoutSeconds: row.timeout_seconds,
  warningDays: row.warning_days,
  criticalDays: row.critical_days,
  gracePeriodSeconds: row.grace_period_seconds ?? 0,
  sniEnabled: Boolean(row.sni_enabled),
  sniHost: row.sni_host,
  validateCertificate: Boolean(row.validate_certificate),
  allowSelfSigned: Boolean(row.allow_self_signed),
  tags: parse<string[]>(row.tags_json, []),
  notes: row.notes,
  owner: row.owner,
  notificationChannelIds: parse<string[]>(row.channel_ids_json, []),
  notificationRecipients: parse<Record<string, string>>(row.notification_recipients_json, {}),
  config: decryptConfigSecrets(parse<Record<string, unknown>>(row.config_json, {})),
  maintenanceWindows: row.maintenance_windows,
  lastStatus: row.last_status,
  nextCheckAt: row.next_check_at,
  createdAt: row.created_at,
  updatedAt: row.updated_at
});

export const rowToResult = (row: any): CheckResult => ({
  id: row.id,
  monitorId: row.monitor_id,
  status: row.status,
  severity: row.severity,
  message: row.message,
  checkedAt: row.checked_at,
  durationMs: row.duration_ms,
  daysRemaining: row.days_remaining,
  validFrom: row.valid_from,
  validUntil: row.valid_until,
  commonName: row.common_name,
  subjectAltNames: parse<string[]>(row.subject_alt_names_json, []),
  issuer: row.issuer,
  serialNumber: row.serial_number,
  fingerprintSha256: row.fingerprint_sha256,
  tlsVersion: row.tls_version,
  cipherSuite: row.cipher_suite,
  tlsGrade: row.tls_grade,
  tlsScore: row.tls_score,
  tlsGradeReasons: parse(row.tls_grade_reasons_json, []),
  tlsSupportedVersions: parse<string[]>(row.tls_supported_versions_json, []),
  sslLabsGrade: row.ssl_labs_grade,
  sslLabsScore: row.ssl_labs_score,
  sslLabsStatus: row.ssl_labs_status,
  sslLabsUrl: row.ssl_labs_url,
  sslLabsCheckedAt: row.ssl_labs_checked_at,
  sslLabsFindings: parse<string[]>(row.ssl_labs_findings_json, []),
  dns: parse(row.dns_json, null),
  flapping: Boolean(row.flapping),
  chain: parse(row.chain_json, []),
  problems: parse<string[]>(row.problems_json, []),
  rawError: row.raw_error
});

export const rowToChannel = (row: any): NotificationChannel => ({
  id: row.id,
  tenantId: row.tenant_id ?? DEFAULT_TENANT_ID,
  name: row.name,
  type: row.type,
  enabled: Boolean(row.enabled),
  config: decryptConfigSecrets(parse<Record<string, unknown>>(row.config_json, {})),
  createdAt: row.created_at,
  updatedAt: row.updated_at
});

export const rowToUser = (row: any): User => ({
  id: row.id,
  email: row.email,
  passwordHash: row.password_hash,
  role: row.role,
  createdAt: row.created_at,
  mfaEnabled: Boolean(row.mfa_enabled)
});

export const rowToIncident = (row: any): Incident => ({
  id: row.id,
  monitorId: row.monitor_id,
  status: row.status,
  severity: row.severity,
  message: row.message,
  startedAt: row.started_at,
  resolvedAt: row.resolved_at,
  acknowledgedAt: row.acknowledged_at,
  acknowledgedBy: row.acknowledged_by,
  assignee: row.assignee,
  notes: parse(row.notes_json, [])
});

export const rowToSubscription = (row: any): StatusSubscription => ({
  id: row.id,
  tags: parse<string[]>(row.tags_json, []),
  type: row.type === "webhook" ? "webhook" : "email",
  target: row.target,
  enabled: Boolean(row.enabled),
  createdAt: row.created_at
});

export const rowToApiToken = (row: any): ApiToken => ({
  id: row.id,
  name: row.name,
  tokenHash: row.token_hash,
  scopes: parse<string[]>(row.scopes_json, []),
  userId: row.user_id,
  createdAt: row.created_at,
  lastUsedAt: row.last_used_at
});

export const rowToDelivery = (row: any): NotificationDelivery => ({
  id: row.id,
  monitorId: row.monitor_id,
  channelId: row.channel_id,
  channelName: row.channel_name,
  provider: row.provider,
  target: row.target,
  severity: row.severity,
  status: row.status,
  deliveryStatus: row.delivery_status === "failed" ? "failed" : "sent",
  message: row.message,
  error: row.error,
  sentAt: row.sent_at
});

export const rowToTenant = (row: any): Tenant => ({
  id: row.id,
  name: row.name,
  slug: row.slug,
  plan: row.plan,
  status: row.status,
  monitorLimit: row.monitor_limit,
  userLimit: row.user_limit,
  teamLimit: row.team_limit ?? 10,
  settings: parse(row.settings_json, {}),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  deletedAt: row.deleted_at
});

export const rowToMembership = (row: any): TenantMembership => ({
  id: row.membership_id ?? row.id,
  tenantId: row.tenant_id,
  userId: row.user_id,
  role: row.role,
  status: row.membership_status ?? row.status ?? "active",
  createdAt: row.created_at,
  updatedAt: row.membership_updated_at ?? row.updated_at,
  tenant: rowToTenant(row),
  userEmail: row.email
});

export const rowToInvite = (row: any): TenantInvite => ({
  id: row.id,
  tenantId: row.tenant_id,
  email: row.email,
  role: row.role,
  token: row.token,
  teamId: row.team_id,
  teamRole: row.team_role,
  invitedByUserId: row.invited_by_user_id,
  acceptedAt: row.accepted_at,
  revokedAt: row.revoked_at,
  expiresAt: row.expires_at,
  createdAt: row.created_at,
  updatedAt: row.updated_at
});

export const rowToUserAlertSettings = (row: any): UserAlertSettings => ({
  tenantId: row.tenant_id,
  userId: row.user_id,
  enabled: Boolean(row.enabled),
  tags: parse<string[]>(row.tags_json, []),
  severities: parse(row.severities_json, []),
  channelIds: parse<string[]>(row.channel_ids_json, []),
  recipients: parse<Record<string, string>>(row.recipients_json, {}),
  updatedAt: row.updated_at
});

export const rowToTeam = (row: any): Team => ({
  id: row.id,
  tenantId: row.tenant_id,
  name: row.name,
  slug: row.slug,
  description: row.description ?? "",
  visibility: row.visibility ?? "tenant_visible",
  status: row.status ?? "active",
  settings: parse(row.settings_json, {}),
  createdByUserId: row.created_by_user_id,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  deletedAt: row.deleted_at
});

export const rowToTeamMembership = (row: any): TeamMembership => ({
  id: row.membership_id ?? row.id,
  tenantId: row.membership_tenant_id ?? row.tenant_id,
  teamId: row.membership_team_id ?? row.team_id,
  userId: row.user_id,
  role: row.role,
  status: row.membership_status ?? row.status ?? "active",
  createdAt: row.membership_created_at ?? row.created_at,
  updatedAt: row.membership_updated_at ?? row.updated_at,
  userEmail: row.email,
  team: row.name ? rowToTeam(row) : undefined
});

export const rowToAuditLog = (row: any): AuditLogEntry => ({
  id: row.id,
  tenantId: row.tenant_id,
  teamId: row.team_id,
  actorUserId: row.actor_user_id,
  targetUserId: row.target_user_id,
  action: row.action,
  metadata: parse(row.metadata_json ?? row.details_json, {}),
  createdAt: row.created_at
});

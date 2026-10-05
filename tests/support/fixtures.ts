import { randomUUID } from "node:crypto";
import { createUserSession } from "../../apps/api/src/auth/passport.js";
import { monitors, tenants, users } from "../../apps/api/src/storage/repositories.js";
import type { CheckResult, Monitor, TenantRole, UserRole } from "../../apps/api/src/types.js";

/* Organizations, accounts and monitors for tests that run against a real
   database. Import it after ./isolatedDatabase.js. */

const suffix = () => randomUUID().slice(0, 8);

export const account = (label: string, role: UserRole = "viewer") => users.create(`${label}-${suffix()}@example.com`, "hash", role);

/** A new organization with its owner and a signed-in session of the owner. */
export const organization = (name: string) => {
  const owner = account(`${name.toLowerCase()}-owner`);
  const tenant = tenants.create(`${name} ${suffix()}`, owner.id);
  return { owner, tenant, session: createUserSession(owner.id) };
};

export const memberOf = (tenantId: string, role: TenantRole) => {
  const user = account(`member-${role}`);
  tenants.addMember(tenantId, user.id, role);
  return { user, session: createUserSession(user.id) };
};

export const monitorIn = (tenantId: string, partial: Partial<Monitor> = {}): Monitor => monitors.create({
  tenantId,
  name: `service-${suffix()}.example.com`,
  host: `service-${suffix()}.example.com`,
  port: 443,
  type: "https",
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
  tags: [],
  notes: null,
  owner: null,
  notificationChannelIds: [],
  notificationRecipients: {},
  config: {},
  maintenanceWindows: null,
  ...partial
});

export const resultFor = (monitor: Monitor, partial: Partial<CheckResult> = {}): CheckResult => ({
  id: randomUUID(),
  monitorId: monitor.id,
  status: "OK",
  severity: "info",
  message: `${monitor.name} answered as expected.`,
  checkedAt: new Date().toISOString(),
  durationMs: 120,
  daysRemaining: 42,
  subjectAltNames: [],
  chain: [],
  problems: [],
  ...partial
});

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { incidents, monitors, tenants, users } from "../apps/api/src/storage/repositories.js";
import { migrate } from "../apps/api/src/storage/db.js";
import type { CheckResult, Monitor } from "../apps/api/src/types.js";

migrate();

const organization = () => {
  const owner = users.create(`owner-${randomUUID().slice(0, 8)}@example.com`, "hash", "viewer");
  return tenants.create(`Incidents ${randomUUID().slice(0, 8)}`, owner.id);
};

const monitorIn = (tenantId: string) => monitors.create({
  tenantId,
  name: "mail.example.com",
  host: "mail.example.com",
  port: 993,
  type: "imaps",
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
  maintenanceWindows: null
}) as Monitor;

const failure = { status: "CRITICAL", severity: "critical", message: "Certificate expired.", checkedAt: new Date().toISOString() } as CheckResult;

describe("incident comments", () => {
  it("stores a required admin comment while acknowledging an incident", () => {
    const tenant = organization();
    const opened = incidents.sync(monitorIn(tenant.id), failure);
    const acknowledged = incidents.acknowledge(opened!.id, tenant.id, "admin@example.com", "Ops", "Renewal started.");

    expect(acknowledged?.acknowledgedBy).toBe("admin@example.com");
    expect(acknowledged?.assignee).toBe("Ops");
    expect(acknowledged?.notes).toHaveLength(1);
    expect(acknowledged?.notes[0]?.text).toBe("Renewal started.");
  });

  it("changes incidents of its own organization only", () => {
    const own = organization();
    const other = organization();
    const opened = incidents.sync(monitorIn(other.id), failure);

    expect(incidents.acknowledge(opened!.id, own.id, "member@example.com", "Own team", "Comment from the own organization.")).toBeNull();
    expect(incidents.addNote(opened!.id, own.id, "member@example.com", "Note from the own organization.")).toBeNull();
    const untouched = incidents.get(opened!.id, other.id);
    expect(untouched?.acknowledgedBy).toBeNull();
    expect(untouched?.notes).toEqual([]);
  });
});

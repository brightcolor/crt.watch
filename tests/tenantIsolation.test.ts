import { removeDatabase } from "./support/isolatedDatabase.js";
import { randomUUID } from "node:crypto";
import cookieParser from "cookie-parser";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { attachSession } from "../apps/api/src/auth/auth.js";
import { db, migrate } from "../apps/api/src/storage/db.js";
import { alerts, appSettings, channels, deliveries, incidents, monitors, results, subscriptions, tenants } from "../apps/api/src/storage/repositories.js";
import { apiRoutes } from "../apps/api/src/routes/index.js";
import { DEFAULT_TENANT_ID } from "../apps/api/src/types.js";
import type { CheckResult } from "../apps/api/src/types.js";
import { account, memberOf, monitorIn, organization, resultFor } from "./support/fixtures.js";
import { serve } from "./support/http.js";

/* Two organizations side by side on one instance: whatever one of them lists,
   acknowledges, deletes or restores stays inside it. */

migrate();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(attachSession);
app.use("/api", apiRoutes);
const client = await serve(app);
const { call } = client;

const failure = { status: "CRITICAL", severity: "critical", message: "Certificate expired.", checkedAt: new Date().toISOString() } as CheckResult;

const alpha = organization("Alpha");
const beta = organization("Beta");
const alphaMonitor = monitorIn(alpha.tenant.id, { name: "alpha.example.com", tags: ["prod"] });
const betaMonitor = monitorIn(beta.tenant.id, { name: "beta.example.com", tags: ["prod"] });
const betaChannelId = randomUUID();
let alphaIncidentId = "";
let betaIncidentId = "";
let betaSubscriptionId = "";
let alphaSubscriptionId = "";

beforeAll(() => {
  for (const monitor of [alphaMonitor, betaMonitor]) {
    results.insert(resultFor(monitor, { message: `${monitor.name} result` }));
    alerts.record(monitor.id, null, "critical", "CRITICAL", `fingerprint-${monitor.id}`, `${monitor.name} alert`);
    deliveries.record({ monitorId: monitor.id, channelId: null, channelName: `${monitor.name} mail`, provider: "email", target: `ops@${monitor.name}`, severity: "critical", status: "CRITICAL", deliveryStatus: "sent", message: `${monitor.name} delivery`, error: null });
  }
  alphaIncidentId = incidents.sync(alphaMonitor, failure)!.id;
  betaIncidentId = incidents.sync(betaMonitor, failure)!.id;
  alphaSubscriptionId = subscriptions.create({ tenantId: alpha.tenant.id, pageSlug: "alpha-status", tags: ["prod"], type: "email", target: "reader@alpha.example" }).id;
  betaSubscriptionId = subscriptions.create({ tenantId: beta.tenant.id, pageSlug: "beta-status", tags: ["prod"], type: "email", target: "reader@beta.example" }).id;
  channels.upsert({ id: betaChannelId, tenantId: beta.tenant.id, name: "Beta hook", type: "webhook", enabled: true, config: { url: "https://hooks.beta.example/notify" }, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  appSettings.set("statusPages", { pages: [{ id: randomUUID(), slug: "beta-status", title: "Beta", description: "", logoUrl: "", tags: ["prod"], hideHostnames: false, enabled: true }] }, beta.tenant.id);
});

afterAll(async () => {
  await client.close();
  removeDatabase();
});

describe("lists", () => {
  it("show only the organization's alerts, incidents, deliveries and subscriptions", async () => {
    const [alertList, incidentList, deliveryList, subscriptionList] = await Promise.all(
      ["/api/alerts", "/api/incidents", "/api/deliveries", "/api/subscriptions"].map((route) => call("GET", route, undefined, { session: alpha.session }))
    );

    expect(alertList.json().map((row: any) => row.monitor_id)).toEqual([alphaMonitor.id]);
    expect(incidentList.json().map((row: any) => row.id)).toEqual([alphaIncidentId]);
    expect(deliveryList.json().map((row: any) => row.monitorId)).toEqual([alphaMonitor.id]);
    expect(subscriptionList.json().map((row: any) => row.id)).toEqual([alphaSubscriptionId]);
  });

  it("follow the member's own organization whatever X-Tenant-Id names", async () => {
    const response = await call("GET", "/api/incidents", undefined, { session: alpha.session, tenantId: beta.tenant.id });

    expect(response.json().map((row: any) => row.id)).toEqual([alphaIncidentId]);
  });

  it("report the latest results of the organization's monitors only", async () => {
    const status = await call("GET", "/api/status", undefined, { session: alpha.session });

    expect(status.json().latestResults.map((row: any) => row.monitorId)).toEqual([alphaMonitor.id]);
  });
});

describe("incidents", () => {
  it("are acknowledged and annotated within their own organization", async () => {
    const ack = await call("POST", `/api/incidents/${betaIncidentId}/ack`, { assignee: "Alpha team", comment: "Comment from Alpha." }, { session: alpha.session });
    const note = await call("POST", `/api/incidents/${betaIncidentId}/notes`, { text: "Note from Alpha." }, { session: alpha.session });

    expect(ack.status).toBe(404);
    expect(ack.json().error).toMatch(/^Incident not found in this organization\./);
    expect(note.status).toBe(404);
    const untouched = incidents.get(betaIncidentId, beta.tenant.id);
    expect(untouched?.acknowledgedBy).toBeNull();
    expect(untouched?.notes).toEqual([]);
  });

  it("of the own organization can be acknowledged", async () => {
    const ack = await call("POST", `/api/incidents/${alphaIncidentId}/ack`, { assignee: "Ops", comment: "Renewal started." }, { session: alpha.session });

    expect(ack.status).toBe(200);
    expect(ack.json()).toMatchObject({ acknowledgedBy: alpha.owner.email, assignee: "Ops" });
  });
});

describe("subscriptions", () => {
  it("are deleted within their own organization", async () => {
    const response = await call("DELETE", `/api/subscriptions/${betaSubscriptionId}`, undefined, { session: alpha.session });

    expect(response.status).toBe(404);
    expect(response.json().error).toMatch(/^Subscription not found in this organization\./);
    expect(subscriptions.list(beta.tenant.id).map((item) => item.id)).toContain(betaSubscriptionId);
  });

  it("are deleted by owners and admins only", async () => {
    const viewer = memberOf(alpha.tenant.id, "viewer");
    const refused = await call("DELETE", `/api/subscriptions/${alphaSubscriptionId}`, undefined, { session: viewer.session });
    const deleted = await call("DELETE", `/api/subscriptions/${alphaSubscriptionId}`, undefined, { session: alpha.session });

    expect(refused.status).toBe(403);
    expect(deleted.status).toBe(204);
    expect(subscriptions.list(alpha.tenant.id)).toEqual([]);
  });
});

describe("notification channels", () => {
  it("are saved within their own organization", async () => {
    const response = await call("POST", "/api/notification-channels", { id: betaChannelId, name: "Alpha hook", type: "webhook", config: { url: "https://hooks.alpha.example/notify" } }, { session: alpha.session });

    expect(response.status).toBe(404);
    expect(response.json().error).toMatch(/^Notification channel not found in this organization\./);
    expect(channels.get(betaChannelId, beta.tenant.id)).toMatchObject({ name: "Beta hook", config: { url: "https://hooks.beta.example/notify" } });
    expect(channels.list(alpha.tenant.id)).toEqual([]);
  });

  it("can be tested by owners and admins only", async () => {
    const member = memberOf(alpha.tenant.id, "member");
    const viewer = memberOf(alpha.tenant.id, "viewer");
    const channel = { name: "Probe", type: "webhook", config: { url: "https://hooks.example.com/probe" } };

    const responses = await Promise.all([member, viewer].map((who) => call("POST", "/api/notification-channels/test", channel, { session: who.session })));

    expect(responses.map((response) => response.status)).toEqual([403, 403]);
    expect(responses[0].json().error).toBe("This needs the owner or admin role in this organization, and your role is member. Ask an owner of the organization for the role.");
  });
});

describe("restore", () => {
  const backup = () => ({
    monitors: [{ name: "restored.example.com", host: "restored.example.com", port: 443, type: "https", tags: ["prod"], notificationChannelIds: [betaChannelId], notificationRecipients: { [betaChannelId]: "ops@alpha.example" } }],
    notificationChannels: [{ id: betaChannelId, name: "Copied hook", type: "webhook", enabled: true, config: { url: "https://hooks.alpha.example/notify" } }],
    notificationRoutes: [{ id: "route-1", name: "Critical", tags: [], severities: ["critical"], channelIds: [betaChannelId], recipients: { [betaChannelId]: "oncall@alpha.example" }, enabled: true }]
  });

  it("gives a channel id of another organization a new id and moves the references along", async () => {
    const response = await call("POST", "/api/export/restore", backup(), { session: alpha.session });

    expect(response.status).toBe(201);
    expect(channels.get(betaChannelId, beta.tenant.id)).toMatchObject({ tenantId: beta.tenant.id, name: "Beta hook", config: { url: "https://hooks.beta.example/notify" } });
    const [copy] = channels.list(alpha.tenant.id);
    expect(copy).toMatchObject({ name: "Copied hook", tenantId: alpha.tenant.id });
    expect(copy.id).not.toBe(betaChannelId);
    const restored = monitors.list(alpha.tenant.id).find((monitor) => monitor.name === "restored.example.com");
    expect(restored?.notificationChannelIds).toEqual([copy.id]);
    expect(restored?.notificationRecipients).toEqual({ [copy.id]: "ops@alpha.example" });
    const [route] = appSettings.notificationRoutes(alpha.tenant.id);
    expect(route.channelIds).toEqual([copy.id]);
    expect(route.recipients).toEqual({ [copy.id]: "oncall@alpha.example" });
  });

  it("refuses status pages whose slug belongs to another organization before writing anything", async () => {
    const before = monitors.list(alpha.tenant.id).length;
    const response = await call("POST", "/api/export/restore", { ...backup(), settings: { statusPages: { pages: [{ slug: "beta-status", title: "Alpha page", tags: ["prod"], hideHostnames: false, enabled: true }] } } }, { session: alpha.session });

    expect(response.status).toBe(409);
    expect(response.json().error).toMatch(/\/public\/status\/beta-status already belongs to another organization/);
    expect(monitors.list(alpha.tenant.id)).toHaveLength(before);
  });

  it("and imports are refused for roles that may not create monitors or change settings", async () => {
    const viewer = memberOf(alpha.tenant.id, "viewer");
    const member = memberOf(alpha.tenant.id, "member");

    const viewerImport = await call("POST", "/api/export/monitors.json", { monitors: [] }, { session: viewer.session });
    const memberImport = await call("POST", "/api/export/monitors.json", { monitors: [] }, { session: member.session });
    const memberRestore = await call("POST", "/api/export/restore", {}, { session: member.session });

    expect(viewerImport.status).toBe(403);
    expect(memberImport.status).toBe(201);
    expect(memberRestore.status).toBe(403);
  });
});

describe("the default organization", () => {
  const backfillMarker = "migration:default-organization-backfill";
  const inDefault = (userId: string) => tenants.forUser(userId).some((membership) => membership.tenantId === DEFAULT_TENANT_ID);

  it("keeps its members across restarts", () => {
    const outsider = account("outsider");
    migrate();

    expect(inDefault(alpha.owner.id)).toBe(false);
    expect(inDefault(beta.owner.id)).toBe(false);
    expect(inDefault(outsider.id)).toBe(false);
  });

  it("adopts accounts from before organizations once, and only those without any membership", () => {
    db.prepare("DELETE FROM settings WHERE key = ?").run(backfillMarker);
    const legacy = account("legacy");
    const legacyAdmin = account("legacy-admin", "super_admin");
    migrate();
    const lateAccount = account("late");
    migrate();

    expect(tenants.forUser(legacy.id).map((membership) => [membership.tenantId, membership.role])).toEqual([[DEFAULT_TENANT_ID, "viewer"]]);
    expect(tenants.forUser(legacyAdmin.id).map((membership) => [membership.tenantId, membership.role])).toEqual([[DEFAULT_TENANT_ID, "owner"]]);
    expect(inDefault(alpha.owner.id)).toBe(false);
    expect(inDefault(lateAccount.id)).toBe(false);
  });
});

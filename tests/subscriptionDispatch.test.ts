import { removeDatabase } from "./support/isolatedDatabase.js";
import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

/* Incident updates to status page subscribers: they reach subscribers of the
   monitor's own organization, and only while a published page shows it. */

const delivery = vi.hoisted(() => ({ postNotification: vi.fn(async (_request: { url: string; body: string }) => ({ status: 200, host: "hooks.example.com" })) }));
vi.mock("../apps/api/src/notifications/delivery.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../apps/api/src/notifications/delivery.js")>()),
  postNotification: delivery.postNotification
}));

import { migrate } from "../apps/api/src/storage/db.js";
import { appSettings, subscriptions } from "../apps/api/src/storage/repositories.js";
import { dispatchStatusSubscriptions } from "../apps/api/src/notifications/service.js";
import type { CheckResult } from "../apps/api/src/types.js";
import { monitorIn, organization, resultFor } from "./support/fixtures.js";

migrate();

const alpha = organization("Alpha");
const beta = organization("Beta");
const alphaWeb = monitorIn(alpha.tenant.id, { name: "Alpha web", tags: ["prod"] });
const alphaInternal = monitorIn(alpha.tenant.id, { name: "Alpha intranet", tags: ["internal"] });
const betaWeb = monitorIn(beta.tenant.id, { name: "Beta web", tags: ["prod"] });
appSettings.set("statusPages", { pages: [{ id: randomUUID(), slug: "alpha-status", title: "Alpha", description: "", logoUrl: "", tags: ["prod"], hideHostnames: false, enabled: true }] }, alpha.tenant.id);

const subscribe = (tenantId: string, tags: string[], target: string) =>
  subscriptions.create({ tenantId, pageSlug: tenantId === alpha.tenant.id ? "alpha-status" : null, tags, type: "webhook", target, enabled: true });

subscribe(alpha.tenant.id, ["prod"], "https://hooks.example.com/alpha-prod");
subscribe(alpha.tenant.id, [], "https://hooks.example.com/alpha-all");
subscribe(beta.tenant.id, ["prod"], "https://hooks.example.com/beta-prod");

const failure = (monitor: typeof alphaWeb): CheckResult => resultFor(monitor, { status: "CRITICAL", severity: "critical", message: "Certificate expired." });
const targets = () => delivery.postNotification.mock.calls.map(([request]) => request.url).sort();

beforeEach(() => delivery.postNotification.mockClear());
afterAll(() => removeDatabase());

describe("status page subscriptions", () => {
  it("hear about a published monitor of their own organization", async () => {
    await dispatchStatusSubscriptions(alphaWeb, failure(alphaWeb), "opened", subscriptions.list(alpha.tenant.id));

    expect(targets()).toEqual(["https://hooks.example.com/alpha-all", "https://hooks.example.com/alpha-prod"]);
    const payload = JSON.parse(delivery.postNotification.mock.calls[0][0].body);
    expect(payload.status_page).toMatch(/\/public\/status\/alpha-status\.html$/);
  });

  it("hear nothing about a monitor that no published page shows, even with a subscription to all labels", async () => {
    await dispatchStatusSubscriptions(alphaInternal, failure(alphaInternal), "opened", subscriptions.list(alpha.tenant.id));

    expect(targets()).toEqual([]);
  });

  it("hear nothing about monitors of an organization that publishes nothing", async () => {
    await dispatchStatusSubscriptions(betaWeb, failure(betaWeb), "opened", subscriptions.list(beta.tenant.id));

    expect(targets()).toEqual([]);
  });

  it("reach subscribers of the monitor's organization only, whatever list they get", async () => {
    await dispatchStatusSubscriptions(alphaWeb, failure(alphaWeb), "opened", subscriptions.list(beta.tenant.id));

    expect(targets()).toEqual([]);
  });
});

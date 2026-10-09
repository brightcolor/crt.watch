import { removeDatabase } from "./support/isolatedDatabase.js";
import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

/* Incident updates to status page subscribers: they reach subscribers of the
   monitor's own organization, only while a published page shows it, and they
   carry what that page shows. */

const delivery = vi.hoisted(() => ({
  postNotification: vi.fn(async (_request: { url: string; body: string }) => ({ status: 200, host: "hooks.example.com" })),
  sendMail: vi.fn(async (_message: { to: string; subject: string; text: string }) => ({}))
}));
vi.mock("../apps/api/src/notifications/delivery.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../apps/api/src/notifications/delivery.js")>()),
  postNotification: delivery.postNotification,
  mailTransport: () => ({ sendMail: delivery.sendMail })
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

beforeEach(() => {
  delivery.postNotification.mockClear();
  delivery.sendMail.mockClear();
});
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

describe("updates to status page subscribers", () => {
  const gamma = organization("Gamma");
  const gammaWeb = monitorIn(gamma.tenant.id, { name: "Gamma web", tags: ["prod", "mail"] });
  appSettings.set("statusPages", { pages: [{ id: randomUUID(), slug: "gamma-status", title: "Gamma", description: "", logoUrl: "", tags: ["prod"], hideHostnames: true, enabled: true }] }, gamma.tenant.id);
  const gammaSubscriber = (type: "webhook" | "email", target: string, pageSlug: string | null = "gamma-status", tags = ["prod"]) =>
    subscriptions.create({ tenantId: gamma.tenant.id, pageSlug, tags, type, target, enabled: true });

  // A result with the certificate, TLS and DNS details of an internal check.
  const detailedFailure = (monitor: typeof alphaWeb): CheckResult => resultFor(monitor, {
    status: "CRITICAL",
    severity: "critical",
    message: "Certificate expired.",
    issuer: "Example Issuing CA",
    fingerprintSha256: "ab".repeat(32),
    validUntil: "2026-09-30T00:00:00.000Z",
    tlsGrade: "F",
    sslLabsGrade: "B",
    dns: { host: monitor.host, checkedAt: new Date().toISOString(), fresh: true, addresses: ["203.0.113.10"], authoritativeNameservers: ["ns1.example.net"], checks: [], mismatches: [], fingerprint: "dns" }
  });
  const sentBody = () => delivery.postNotification.mock.calls[0][0].body;

  it("carry the monitor as the status page shows it", async () => {
    const result = detailedFailure(alphaWeb);
    const [subscriber] = subscriptions.list(alpha.tenant.id).filter((subscription) => subscription.target.endsWith("/alpha-prod"));

    await dispatchStatusSubscriptions(alphaWeb, result, "opened", [subscriber]);

    expect(JSON.parse(sentBody())).toEqual({
      event: "opened",
      monitor_id: alphaWeb.id,
      monitor_name: "Alpha web",
      host: alphaWeb.host,
      port: 443,
      status: "critical",
      severity: "critical",
      message: "Certificate expired.",
      days_remaining: 42,
      checked_at: result.checkedAt,
      status_page: expect.stringMatching(/\/public\/status\/alpha-status\.html$/)
    });
  });

  it("carry no host or port from a page that hides host names", async () => {
    await dispatchStatusSubscriptions(gammaWeb, detailedFailure(gammaWeb), "opened", [gammaSubscriber("webhook", "https://hooks.example.com/gamma")]);

    const payload = JSON.parse(sentBody());
    expect(payload).toMatchObject({ monitor_name: "Gamma web", status: "critical", message: "Certificate expired." });
    expect(payload).not.toHaveProperty("host");
    expect(payload).not.toHaveProperty("port");
    expect(sentBody()).not.toContain(gammaWeb.host);
  });

  it("follow the page with their labels when they name no page", async () => {
    await dispatchStatusSubscriptions(gammaWeb, detailedFailure(gammaWeb), "opened", [gammaSubscriber("webhook", "https://hooks.example.com/gamma-labels", null)]);

    expect(sentBody()).not.toContain(gammaWeb.host);
  });

  it("carry no host or port when their page no longer exists", async () => {
    await dispatchStatusSubscriptions(gammaWeb, detailedFailure(gammaWeb), "opened", [gammaSubscriber("webhook", "https://hooks.example.com/gamma-gone", "gamma-retired", ["prod", "mail"])]);

    expect(JSON.parse(sentBody())).not.toHaveProperty("host");
  });

  it("by email name the monitor without its host on a page that hides host names", async () => {
    await dispatchStatusSubscriptions(gammaWeb, detailedFailure(gammaWeb), "opened", [gammaSubscriber("email", "reader@gamma.example")]);

    const [message] = delivery.sendMail.mock.calls[0];
    expect(message).toMatchObject({ to: "reader@gamma.example", subject: "[crt.watch Status] Incident: Gamma web" });
    expect(message.text).toContain("Gamma web: Certificate expired.");
    expect(JSON.stringify(message)).not.toContain(gammaWeb.host);
  });
});

import { removeDatabase } from "./support/isolatedDatabase.js";
import { randomUUID } from "node:crypto";
import cookieParser from "cookie-parser";
import express from "express";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/* What the public sees: only monitors that their own organization has put on
   an enabled status page. Opt-in messages are not sent from here. */

const service = vi.hoisted(() => ({ sendStatusSubscriptionOptIn: vi.fn(async (_subscription: unknown) => undefined) }));
vi.mock("../apps/api/src/notifications/service.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../apps/api/src/notifications/service.js")>()),
  sendStatusSubscriptionOptIn: service.sendStatusSubscriptionOptIn
}));

import { attachSession } from "../apps/api/src/auth/auth.js";
import { db, migrate } from "../apps/api/src/storage/db.js";
import { appSettings, incidents, monitors, results, subscriptions } from "../apps/api/src/storage/repositories.js";
import { apiRoutes } from "../apps/api/src/routes/index.js";
import { publicRoutes } from "../apps/api/src/routes/publicRoutes.js";
import { findPublishedPage, isPublished, statusPageConflict } from "../apps/api/src/status/publication.js";
import type { CheckResult, StatusPageConfig } from "../apps/api/src/types.js";
import { monitorIn, organization, resultFor } from "./support/fixtures.js";
import { serve } from "./support/http.js";

migrate();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(attachSession);
app.use("/api", apiRoutes);
app.use("/public", publicRoutes);
const client = await serve(app);
const { call } = client;

const page = (partial: Partial<StatusPageConfig>): StatusPageConfig => ({ id: randomUUID(), slug: "page", title: "Status", description: "", logoUrl: "", tags: [], hideHostnames: false, enabled: true, ...partial });

const alpha = organization("Alpha");
const beta = organization("Beta");
const alphaWeb = monitorIn(alpha.tenant.id, { name: "Alpha web", host: "www.alpha.example", tags: ["prod", "web"] });
const alphaInternal = monitorIn(alpha.tenant.id, { name: "Alpha intranet", host: "intranet.alpha.example", tags: ["internal"] });
const betaWeb = monitorIn(beta.tenant.id, { name: "Beta web", host: "www.beta.example", tags: ["prod", "web"] });

beforeAll(() => {
  // Alpha is the older organization, so it holds label addresses that Beta publishes too.
  db.prepare("UPDATE tenants SET created_at = ? WHERE id = ?").run("2020-01-01T00:00:00.000Z", alpha.tenant.id);
  for (const monitor of [alphaWeb, alphaInternal, betaWeb]) {
    const result = resultFor(monitor, { daysRemaining: 21 });
    results.insert(result);
    monitors.markChecked(monitor, result);
  }
  const opened = incidents.sync(alphaWeb, { status: "CRITICAL", severity: "critical", message: "Certificate expired.", checkedAt: new Date().toISOString() } as CheckResult)!;
  incidents.acknowledge(opened.id, alpha.tenant.id, alpha.owner.email, "Night shift", "Internal note about the renewal.");
  appSettings.set("statusPages", { pages: [page({ slug: "alpha-status", title: "Alpha status", tags: ["prod"] }), page({ slug: "alpha-hidden", title: "Alpha hidden hosts", tags: ["web"], hideHostnames: true }), page({ slug: "alpha-off", title: "Alpha disabled", tags: ["internal"], enabled: false })] }, alpha.tenant.id);
});

beforeEach(() => service.sendStatusSubscriptionOptIn.mockClear());

afterAll(async () => {
  await client.close();
  removeDatabase();
});

describe("public status pages", () => {
  it("show exactly the monitors of the published page", async () => {
    const response = await call("GET", "/public/status/alpha-status");

    expect(response.status).toBe(200);
    expect(response.json().monitors.map((monitor: any) => monitor.name)).toEqual(["Alpha web"]);
    expect(response.text).not.toContain("beta");
    expect(response.text).not.toContain("intranet");
  });

  it("answer under the labels of a published page as well", async () => {
    const response = await call("GET", "/public/status/prod");

    expect(response.status).toBe(200);
    expect(response.json().title).toBe("Alpha status");
    expect(response.json().monitors.map((monitor: any) => monitor.name)).toEqual(["Alpha web"]);
  });

  it("answer 404 for labels, empty addresses and disabled pages that nobody published", async () => {
    const addresses = ["internal", "prod+web", "%2B", ",", "alpha-off", "beta", "does-not-exist"];
    const responses = await Promise.all(addresses.map((address) => call("GET", `/public/status/${address}`)));
    const page = await call("GET", "/public/status/internal.html", undefined, { headers: { accept: "text/html" } });

    expect(responses.map((response) => response.status)).toEqual(addresses.map(() => 404));
    expect(responses[0].json().error).toMatch(/^No status page is published at this address\./);
    expect(page.status).toBe(404);
    expect(page.text).toContain("Status page not found");
    expect(page.text).not.toContain("intranet");
  });

  it("leave out host names in the JSON when the page hides them", async () => {
    const response = await call("GET", "/public/status/alpha-hidden");
    const html = await call("GET", "/public/status/alpha-hidden.html", undefined, { headers: { accept: "text/html" } });

    expect(response.json().monitors[0]).not.toHaveProperty("host");
    expect(response.json().monitors[0]).not.toHaveProperty("port");
    expect(response.text).not.toContain("www.alpha.example");
    expect(html.text).not.toContain("www.alpha.example");
  });

  it("show incidents without acknowledgements, assignees or internal notes", async () => {
    const [incident] = (await call("GET", "/public/status/alpha-status")).json().incidents;

    expect(incident).toMatchObject({ status: "CRITICAL", message: "Certificate expired." });
    expect(Object.keys(incident).sort()).toEqual(["message", "monitorId", "resolvedAt", "severity", "startedAt", "status"]);
  });

  it("stop answering while the organization is suspended", async () => {
    db.prepare("UPDATE tenants SET status = 'suspended' WHERE id = ?").run(alpha.tenant.id);
    try {
      expect((await call("GET", "/public/status/alpha-status")).status).toBe(404);
      expect(isPublished(alphaWeb)).toBe(false);
    } finally {
      db.prepare("UPDATE tenants SET status = 'active' WHERE id = ?").run(alpha.tenant.id);
    }
  });
});

describe("badges", () => {
  const svgValue = (svg: string) => svg.match(/<title>([^<]*)<\/title>/)?.[1] ?? "";

  it("show a monitor that a published page covers", async () => {
    const badge = await call("GET", `/public/badge/${alphaWeb.id}.svg`);

    expect(badge.headers.get("content-type")).toMatch(/image\/svg\+xml/);
    expect(svgValue(badge.text)).toBe("Alpha web: OK 21d");
  });

  it("read unknown for a monitor that no published page covers, the same as for a missing one", async () => {
    const unpublished = await call("GET", `/public/badge/${alphaInternal.id}.svg`);
    const foreign = await call("GET", `/public/badge/${betaWeb.id}.svg`);
    const missing = await call("GET", `/public/badge/${randomUUID()}.svg`);

    expect([unpublished, foreign, missing].map((badge) => svgValue(badge.text))).toEqual(["monitor: UNKNOWN", "monitor: UNKNOWN", "monitor: UNKNOWN"]);
  });

  it("for labels roll up the published page and read unknown elsewhere", async () => {
    const published = await call("GET", "/public/badge/tags/prod.svg");
    const unpublished = await call("GET", "/public/badge/tags/internal.svg");

    expect(svgValue(published.text)).toBe("Alpha status: ok");
    expect(svgValue(unpublished.text)).toBe("internal: unknown");
  });
});

describe("label addresses shared by several organizations", () => {
  it("belong to the default organization first and then to the oldest", () => {
    appSettings.set("statusPages", { pages: [page({ slug: "beta-status", title: "Beta status", tags: ["prod"] })] }, beta.tenant.id);
    try {
      expect(findPublishedPage("prod")?.tenantId).toBe(alpha.tenant.id);
      expect(findPublishedPage("beta-status")?.tenantId).toBe(beta.tenant.id);
    } finally {
      appSettings.delete("statusPages", beta.tenant.id);
    }
  });
});

describe("status page settings", () => {
  it("refuse a slug that another organization uses, also for a disabled page", async () => {
    const taken = await call("PUT", "/api/settings/status-pages", { pages: [{ slug: "alpha-status", title: "Beta page", tags: [], hideHostnames: false, enabled: true }] }, { session: beta.session });
    const disabled = await call("PUT", "/api/settings/status-pages", { pages: [{ slug: "alpha-off", title: "Beta page", tags: [], hideHostnames: false, enabled: true }] }, { session: beta.session });

    expect(taken.status).toBe(409);
    expect(taken.json().error).toBe("The address /public/status/alpha-status already belongs to another organization. Choose a different slug for the page \"Beta page\".");
    expect(disabled.status).toBe(409);
    expect(appSettings.statusPages(beta.tenant.id).pages).toEqual([]);
  });

  it("refuse the same slug twice and explain the slug format", async () => {
    expect(statusPageConflict(beta.tenant.id, [{ slug: "twice", title: "A" }, { slug: "twice", title: "B" }])).toBe("Two status pages use the slug \"twice\". Give each page its own slug.");
    const invalid = await call("PUT", "/api/settings/status-pages", { pages: [{ slug: "Not Valid", title: "Beta page", tags: [], hideHostnames: false, enabled: true }] }, { session: beta.session });

    expect(invalid.status).toBe(400);
    expect(invalid.json().error).toBe("A status page slug may contain lowercase letters, digits and hyphens.");
  });

  it("save a free slug", async () => {
    const saved = await call("PUT", "/api/settings/status-pages", { pages: [{ slug: "beta-own", title: "Beta own", tags: ["web"], hideHostnames: false, enabled: true }] }, { session: beta.session });

    expect(saved.status).toBe(200);
    expect((await call("GET", "/public/status/beta-own")).json().monitors.map((monitor: any) => monitor.name)).toEqual(["Beta web"]);
  });
});

describe("subscriptions", () => {
  it("belong to the organization of the published page", async () => {
    const response = await call("POST", "/public/status/alpha-status/subscribe", { type: "email", target: "reader@example.com" });

    expect(response.status).toBe(202);
    expect(response.json()).not.toHaveProperty("tenantId");
    const [stored] = subscriptions.list(alpha.tenant.id);
    expect(stored).toMatchObject({ tenantId: alpha.tenant.id, pageSlug: "alpha-status", tags: ["prod"], target: "reader@example.com", enabled: false });
    expect(service.sendStatusSubscriptionOptIn).toHaveBeenCalledTimes(1);
  });

  it("are made on published pages only", async () => {
    const response = await call("POST", "/public/status/internal/subscribe", { type: "email", target: "reader@example.com" });

    expect(response.status).toBe(404);
    expect(service.sendStatusSubscriptionOptIn).not.toHaveBeenCalled();
  });

  it("lead back to their page after the confirmation", async () => {
    const [stored] = subscriptions.list(alpha.tenant.id);
    const response = await call("GET", `/public/subscriptions/${stored.id}/confirm`, undefined, { redirect: "manual" });

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/public/status/alpha-status.html?subscription=confirmed");
  });
});

import { removeDatabase } from "./support/isolatedDatabase.js";
import dnsPromises from "node:dns/promises";
import express from "express";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { attachSession } from "../apps/api/src/auth/auth.js";
import { migrate } from "../apps/api/src/storage/db.js";
import { incidents } from "../apps/api/src/storage/repositories.js";
import { apiRoutes } from "../apps/api/src/routes/index.js";
import type { CheckResult } from "../apps/api/src/types.js";
import { memberOf, monitorIn, organization } from "./support/fixtures.js";
import { readCookies, serve } from "./support/http.js";

/* Which organization role each action needs: viewers read, members operate
   monitors and their incidents, owners and admins manage settings. */

migrate();

const app = express();
app.use(express.json());
app.use(readCookies);
app.use(attachSession);
app.use("/api", apiRoutes);
const client = await serve(app);
const { call } = client;

const org = organization("Roles");
const viewer = memberOf(org.tenant.id, "viewer");
const member = memberOf(org.tenant.id, "member");
const failure = { status: "CRITICAL", severity: "critical", message: "Certificate expired.", checkedAt: new Date().toISOString() } as CheckResult;
const openIncident = () => incidents.sync(monitorIn(org.tenant.id), failure)!;

afterEach(() => vi.restoreAllMocks());
afterAll(async () => {
  await client.close();
  removeDatabase();
});

describe("incidents", () => {
  it("are acknowledged with the member role", async () => {
    const incident = openIncident();

    const refused = await call("POST", `/api/incidents/${incident.id}/ack`, { assignee: "Ops", comment: "On it." }, { session: viewer.session });
    expect(refused.status).toBe(403);
    expect(refused.json().error).toBe("This needs the owner, admin or member role in this organization, and your role is viewer. Ask an owner of the organization for the role.");
    expect(incidents.get(incident.id, org.tenant.id)).toMatchObject({ acknowledgedBy: null, assignee: null, notes: [] });

    const acknowledged = await call("POST", `/api/incidents/${incident.id}/ack`, { assignee: "Ops", comment: "On it." }, { session: member.session });
    expect(acknowledged.status).toBe(200);
    expect(acknowledged.json()).toMatchObject({ acknowledgedBy: member.user.email, assignee: "Ops" });
  });

  it("take notes with the member role", async () => {
    const incident = openIncident();

    const refused = await call("POST", `/api/incidents/${incident.id}/notes`, { text: "Renewal ordered." }, { session: viewer.session });
    expect(refused.status).toBe(403);
    expect(incidents.get(incident.id, org.tenant.id)?.notes).toEqual([]);

    const noted = await call("POST", `/api/incidents/${incident.id}/notes`, { text: "Renewal ordered." }, { session: member.session });
    expect(noted.status).toBe(200);
    expect(noted.json().notes.map((note: { author: string; text: string }) => [note.author, note.text])).toEqual([[member.user.email, "Renewal ordered."]]);
  });
});

describe("discovery for a domain", () => {
  it("suggests monitors with the member role, the role that creates them", async () => {
    const resolveMx = vi.spyOn(dnsPromises, "resolveMx").mockResolvedValue([{ exchange: "mx.discovered.example", priority: 10 }]);

    const refused = await call("POST", "/api/discover", { domain: "discovered.example" }, { session: viewer.session });
    expect(refused.status).toBe(403);
    expect(refused.json().error).toMatch(/needs the owner, admin or member role.*your role is viewer/);
    expect(resolveMx).not.toHaveBeenCalled();

    const suggested = await call("POST", "/api/discover", { domain: "discovered.example" }, { session: member.session });
    expect(suggested.status).toBe(200);
    expect(suggested.json().monitors.map((item: { host: string; port: number }) => `${item.host}:${item.port}`)).toContain("mx.discovered.example:993");
  });
});

describe("the certificate transparency check", () => {
  it("runs with the owner or admin role, the role that manages the CT watch", async () => {
    const admin = memberOf(org.tenant.id, "admin");

    const refused = await Promise.all([viewer, member].map((who) => call("POST", "/api/ct-watch/check", {}, { session: who.session })));
    expect(refused.map((response) => response.status)).toEqual([403, 403]);
    expect(refused[1].json().error).toBe("This needs the owner or admin role in this organization, and your role is member. Ask an owner of the organization for the role.");

    const checked = await Promise.all([org, admin].map((who) => call("POST", "/api/ct-watch/check", {}, { session: who.session })));
    expect(checked.map((response) => response.status)).toEqual([200, 200]);
    expect(checked[0].json()).toEqual({ enabled: false, changes: [] });
  });
});

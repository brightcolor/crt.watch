import { removeDatabase } from "./support/isolatedDatabase.js";
import express from "express";
import { afterAll, describe, expect, it } from "vitest";
import { attachSession } from "../apps/api/src/auth/auth.js";
import { db, migrate } from "../apps/api/src/storage/db.js";
import { appSettings, channels, monitors } from "../apps/api/src/storage/repositories.js";
import { apiRoutes } from "../apps/api/src/routes/index.js";
import { monitorIn, organization } from "./support/fixtures.js";
import { readCookies, serve } from "./support/http.js";

/* An organization holds at most as many monitors as its monitor limit allows,
   whichever way they are created. The tests use small limits instead of the
   default of 50. */

migrate();

const app = express();
app.use(express.json());
app.use(readCookies);
app.use(attachSession);
app.use("/api", apiRoutes);
const client = await serve(app);
const { call } = client;

afterAll(async () => {
  await client.close();
  removeDatabase();
});

/** A new organization with the given monitor limit and that many monitors already in it. */
const organizationWith = (limit: number, existing = 0) => {
  const org = organization("Quota");
  db.prepare("UPDATE tenants SET monitor_limit = ? WHERE id = ?").run(limit, org.tenant.id);
  for (let index = 0; index < existing; index += 1) monitorIn(org.tenant.id);
  return { ...org, count: () => monitors.list(org.tenant.id).length };
};

const entry = (name: string) => ({ name, host: `${name}.example.com`, port: 443, type: "https" });

describe("the JSON import", () => {
  it("imports every monitor that fits into the limit", async () => {
    const org = organizationWith(3, 1);

    const response = await call("POST", "/api/export/monitors.json", { monitors: [entry("first"), entry("second")] }, { session: org.session });

    expect(response.status).toBe(201);
    expect(response.json().imported).toBe(2);
    expect(org.count()).toBe(3);
  });

  it("refuses an import beyond the limit before it creates a monitor", async () => {
    const org = organizationWith(3, 1);

    const response = await call("POST", "/api/export/monitors.json", { monitors: [entry("first"), entry("second"), entry("third")] }, { session: org.session });

    expect(response.status).toBe(402);
    expect(response.json().error).toBe("This import holds 3 monitors, and the organization has room for 2 more within its limit of 3 monitors. Import fewer monitors or delete monitors it no longer needs, or ask the operator of this crt.watch instance to raise the limit.");
    expect(org.count()).toBe(1);
  });

  it("counts only the entries that are valid monitors", async () => {
    const org = organizationWith(2);

    const response = await call("POST", "/api/export/monitors.json", { monitors: [entry("first"), { ...entry("second"), type: "gopher" }, entry("third")] }, { session: org.session });

    expect(response.status).toBe(201);
    expect(response.json().monitors.map((monitor: { name: string }) => monitor.name)).toEqual(["first", "third"]);
  });
});

describe("a restore", () => {
  const backup = () => ({
    monitors: [entry("restored-one"), entry("restored-two")],
    notificationChannels: [{ name: "Restored hook", type: "webhook", enabled: true, config: { url: "https://hooks.example.com/restored" } }],
    settings: { retention: { checkResultsDays: 30, alertHistoryDays: 30 } }
  });

  it("restores every monitor that fits into the limit", async () => {
    const org = organizationWith(3, 1);

    const response = await call("POST", "/api/export/restore", backup(), { session: org.session });

    expect(response.status).toBe(201);
    expect(org.count()).toBe(3);
  });

  it("refuses a backup beyond the limit before it writes anything", async () => {
    const org = organizationWith(2, 1);
    const retention = appSettings.retention(org.tenant.id);

    const response = await call("POST", "/api/export/restore", backup(), { session: org.session });

    expect(response.status).toBe(402);
    expect(response.json().error).toBe("This backup holds 2 monitors, and the organization has room for 1 more within its limit of 2 monitors. Remove monitors from the backup or delete monitors the organization no longer needs, then restore again, or ask the operator of this crt.watch instance to raise the limit.");
    expect(org.count()).toBe(1);
    expect(channels.list(org.tenant.id)).toEqual([]);
    expect(appSettings.retention(org.tenant.id)).toEqual(retention);
  });
});

describe("bulk and discovery imports", () => {
  it("fill the limit with the bulk import and report the lines beyond it", async () => {
    const org = organizationWith(3);

    const response = await call("POST", "/api/monitors/bulk", { text: ["one.example.com", "two.example.com", "three.example.com", "four.example.com"].join("\n") }, { session: org.session });

    expect(response.status).toBe(207);
    expect(response.json().imported).toBe(3);
    expect(response.json().errors).toEqual([{ line: "four.example.com", error: "This organization has reached its limit of 3 monitors. Delete monitors it no longer needs, or ask the operator of this crt.watch instance to raise the limit." }]);
    expect(org.count()).toBe(3);
  });

  it("fill the limit with discovered monitors and report the ones beyond it", async () => {
    const org = organizationWith(3);
    const discovered = ["one", "two", "three", "four"].map((name) => ({ ...entry(name), tags: ["discovered"] }));

    const response = await call("POST", "/api/discovery/import", { monitors: discovered }, { session: org.session });

    expect(response.status).toBe(207);
    expect(response.json().imported).toBe(3);
    expect(response.json().errors.map((item: { monitor: { name: string } }) => item.monitor.name)).toEqual(["four"]);
    expect(org.count()).toBe(3);
  });
});

describe("a single monitor", () => {
  it("is refused at the limit with the limit and the next step", async () => {
    const org = organizationWith(1, 1);
    const [existing] = monitors.list(org.tenant.id);

    const created = await call("POST", "/api/monitors", entry("extra"), { session: org.session });
    const cloned = await call("POST", `/api/monitors/${existing.id}/clone`, {}, { session: org.session });

    expect([created.status, cloned.status]).toEqual([402, 402]);
    expect(created.json().error).toBe("This organization has reached its limit of 1 monitor. Delete monitors it no longer needs, or ask the operator of this crt.watch instance to raise the limit.");
    expect(cloned.json().error).toBe(created.json().error);
    expect(org.count()).toBe(1);
  });
});

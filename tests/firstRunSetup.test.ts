import { databaseDirectory, removeDatabase } from "./support/isolatedDatabase.js";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import cookieParser from "cookie-parser";
import express from "express";
import { afterAll, describe, expect, it } from "vitest";
import { attachSession } from "../apps/api/src/auth/auth.js";
import { passwordRule } from "../apps/api/src/auth/passwords.js";
import { announceSetup, currentSetupCode, setupCodeCommand, setupRequired } from "../apps/api/src/auth/setup.js";
import { env, integerSetting } from "../apps/api/src/config/env.js";
import { db, migrate } from "../apps/api/src/storage/db.js";
import { auditLogs, tenants, users } from "../apps/api/src/storage/repositories.js";
import { apiRoutes } from "../apps/api/src/routes/index.js";
import { publicRoutes } from "../apps/api/src/routes/publicRoutes.js";
import { pageHandler, setupClosedPage } from "../apps/api/src/render/pages.js";
import { authLimiter } from "../apps/api/src/security/rateLimits.js";
import { serve } from "./support/http.js";

/* A fresh instance: every page leads to the setup, which asks for the code
   from the server log, creates the first administrator and then closes. */

migrate();

const webDist = fs.mkdtempSync(path.join(os.tmpdir(), "crtwatch-web-"));
fs.writeFileSync(path.join(webDist, "index.html"), "<!doctype html><title>crt.watch</title><div id=\"root\"></div>");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(attachSession);
app.use("/api", apiRoutes);
app.use("/public", publicRoutes);
app.use(express.static(webDist, { index: false }));
app.get("*", pageHandler(webDist, true));
const client = await serve(app);
const { call } = client;

const logged: string[] = [];
const password = "a-long-enough-password";
const administrator = { email: "operator@example.com", password, organizationName: "Operations" };

const cli = (args: string[], databasePath = process.env.DATABASE_PATH!) => spawnSync(process.execPath, [path.resolve("node_modules/tsx/dist/cli.mjs"), path.resolve("apps/api/src/cli.ts"), ...args], {
  encoding: "utf8",
  env: { ...process.env, DATABASE_PATH: databasePath, BASE_URL: "https://crt.example.test" }
});

afterAll(async () => {
  await client.close();
  fs.rmSync(webDist, { recursive: true, force: true });
  removeDatabase();
});

describe("while no administrator exists", () => {
  it("every page leads to /setup, and the API, public pages and static files stay reachable", async () => {
    const pages = await Promise.all(["/", "/login", "/register", "/app/reports", "/app/monitors/1"].map((route) => call("GET", route, undefined, { redirect: "manual" })));
    const setupPage = await call("GET", "/setup");
    const health = await call("GET", "/api/health");
    const publicStatus = await call("GET", "/public/status/anything");
    const asset = await call("GET", "/index.html");

    expect(pages.map((response) => [response.status, response.headers.get("location")])).toEqual(pages.map(() => [302, "/setup"]));
    expect(setupPage.status).toBe(200);
    expect(setupPage.text).toContain("<div id=\"root\"></div>");
    expect(health.json()).toEqual({ ok: true });
    expect(publicStatus.status).toBe(404);
    expect(asset.status).toBe(200);
  });

  it("the configuration names the command for the code but never the code", async () => {
    const code = announceSetup("https://crt.example.test", (message) => logged.push(message))!;
    const config = await call("GET", "/api/auth/config");

    expect(config.json()).toMatchObject({ setupRequired: true, setupCodeCommand, passwordMinLength: env.passwordMinLength });
    expect(config.text).not.toContain(code);
    expect(code).toMatch(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/);
  });

  it("the server log carries a fresh code with the address and the command at every start", () => {
    const first = currentSetupCode();
    const second = announceSetup("https://crt.example.test/", (message) => logged.push(message));

    expect(second).not.toBe(first);
    expect(currentSetupCode()).toBe(second);
    expect(logged.at(-1)).toBe([
      "crt.watch is not set up yet: no administrator account exists.",
      `Open https://crt.example.test/setup and create the first administrator with this setup code: ${second}`,
      `The code changes at every start. To print the current one: ${setupCodeCommand}`
    ].join("\n"));
  });

  it("the command prints the current code", () => {
    const run = cli(["setup-code"]);

    expect(run.status).toBe(0);
    expect(run.stdout).toBe(`Setup code: ${currentSetupCode()}\nOpen https://crt.example.test/setup and enter it to create the first administrator.\n`);
  });

  it("registration waits for the setup", async () => {
    const response = await call("POST", "/api/auth/register", { email: "early@example.com", password, organizationName: "Early bird" });

    expect(response.status).toBe(409);
    expect(response.json().error).toBe("This crt.watch instance is not set up yet. Registration opens once the operator has created the first administrator account.");
    expect(users.count()).toBe(0);
  });

  it("the setup refuses a missing or wrong code and a short password", async () => {
    const missing = await call("POST", "/api/auth/setup", administrator);
    const wrong = await call("POST", "/api/auth/setup", { ...administrator, setupCode: "AAAA-BBBB-CCCC-DDDD" });
    const short = await call("POST", "/api/auth/setup", { ...administrator, password: "short", setupCode: currentSetupCode() });

    expect(missing.status).toBe(400);
    expect(missing.json().error).toBe(`Enter the setup code. It is in the server log, or print it on the server with: ${setupCodeCommand}`);
    expect(wrong.status).toBe(403);
    expect(wrong.json().error).toBe(`The setup code is not valid. Use the code from the server log of the current start, or print it on the server with: ${setupCodeCommand}`);
    expect(short.status).toBe(400);
    expect(short.json().error).toBe(`Password must be at least ${env.passwordMinLength} characters long.`);
    expect(users.count()).toBe(0);
  });

  it("wrong codes count against the sign-in limit", async () => {
    const statuses: number[] = [];
    for (let attempt = 0; attempt <= env.authRateLimitMaxAttempts; attempt += 1) {
      statuses.push((await call("POST", "/api/auth/setup", { ...administrator, setupCode: "WRONG-CODE" })).status);
    }
    await authLimiter.resetKey("127.0.0.1");
    await authLimiter.resetKey("::ffff:127.0.0.1");

    expect(statuses.at(-1)).toBe(429);
  });
});

describe("the setup", () => {
  it("creates a signed-in administrator who owns an organization, records it and closes", async () => {
    const code = currentSetupCode()!;
    // Case, spaces and hyphens do not matter when the code is typed in.
    const response = await call("POST", "/api/auth/setup", { ...administrator, setupCode: ` ${code.toLowerCase().replaceAll("-", " ")} ` });

    expect(response.status).toBe(201);
    expect(response.headers.get("set-cookie")).toMatch(/^crtwatch_session=/);
    const created = users.findByEmail(administrator.email)!;
    expect(created.role).toBe("super_admin");
    const [membership] = tenants.forUser(created.id);
    expect(membership).toMatchObject({ role: "owner", tenant: { name: "Operations" } });
    expect(auditLogs.list(membership.tenantId).map((entry) => [entry.action, entry.actorUserId])).toEqual([["setup.completed", created.id]]);
    expect(setupRequired()).toBe(false);
    expect(currentSetupCode()).toBeNull();
  });

  it("answers 404 afterwards, as page and as API", async () => {
    const again = await call("POST", "/api/auth/setup", { ...administrator, email: "second@example.com", setupCode: "AAAA-BBBB-CCCC-DDDD" });
    const page = await call("GET", "/setup");
    const config = await call("GET", "/api/auth/config");
    const front = await call("GET", "/", undefined, { redirect: "manual" });

    expect(again.status).toBe(404);
    expect(again.json().error).toBe("The setup of this crt.watch instance is complete. Sign in instead, or ask an administrator for an account.");
    expect(page.status).toBe(404);
    expect(page.text).toBe(setupClosedPage);
    expect(config.json().setupRequired).toBe(false);
    expect(config.json()).not.toHaveProperty("setupCodeCommand");
    expect(front.status).toBe(200);
    expect(users.countAdmins()).toBe(1);
  });

  it("leaves the command nothing to print", () => {
    const run = cli(["setup-code"]);

    expect(run.status).toBe(1);
    expect(run.stderr).toBe("The setup of this crt.watch instance is complete, so there is no setup code. Sign in at https://crt.example.test/login, or ask an administrator for an account.\n");
  });

  it("is followed by registrations that never get a platform role", async () => {
    const response = await call("POST", "/api/auth/register", { email: "customer@example.com", password, organizationName: "Customer" });

    expect(response.status).toBe(201);
    expect(users.findByEmail("customer@example.com")?.role).toBe("viewer");
  });

  it("opens again when no administrator is left, with a new code", () => {
    db.prepare("UPDATE users SET role = 'viewer' WHERE email = ?").run(administrator.email);
    try {
      expect(setupRequired()).toBe(true);
      expect(announceSetup("https://crt.example.test", () => undefined)).toMatch(/^[A-Z2-9]{4}-/);
    } finally {
      db.prepare("UPDATE users SET role = 'super_admin' WHERE email = ?").run(administrator.email);
      announceSetup("https://crt.example.test", () => undefined);
    }
    expect(currentSetupCode()).toBeNull();
  });
});

describe("the setup-code command", () => {
  it("explains its usage", () => {
    const run = cli(["something-else"]);

    expect(run.status).toBe(2);
    expect(run.stderr).toContain("Unknown command \"something-else\".");
    expect(run.stderr).toContain("setup-code   print the setup code for creating the first administrator");
  });

  it("asks for a first start when the database has no tables yet", () => {
    const empty = path.join(databaseDirectory, "empty.sqlite");
    const run = cli(["setup-code"], empty);

    expect(run.status).toBe(1);
    expect(run.stderr).toBe(`The database ${empty} has no tables yet. Start crt.watch once; it creates the database and writes the setup code to its log.\n`);
  });
});

describe("the password rule", () => {
  it("follows PASSWORD_MIN_LENGTH", () => {
    expect(passwordRule(16).safeParse("twelve-chars").error?.issues[0]?.message).toBe("Password must be at least 16 characters long.");
    expect(passwordRule(8).safeParse("eight-ch").success).toBe(true);
    expect(integerSetting({ PASSWORD_MIN_LENGTH: "20" }, "PASSWORD_MIN_LENGTH", 12, 8, 128)).toBe(20);
    expect(() => integerSetting({ PASSWORD_MIN_LENGTH: "6" }, "PASSWORD_MIN_LENGTH", 12, 8, 128)).toThrow(/PASSWORD_MIN_LENGTH must be a whole number from 8 to 128/);
  });
});

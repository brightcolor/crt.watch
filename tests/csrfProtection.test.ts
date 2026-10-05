import { removeDatabase } from "./support/isolatedDatabase.js";
import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import express from "express";
import { afterAll, describe, expect, it } from "vitest";
import { attachSession, createPlainApiToken, hashToken } from "../apps/api/src/auth/auth.js";
import { configurePassport } from "../apps/api/src/auth/passport.js";
import { apiRoutes } from "../apps/api/src/routes/index.js";
import { csrfTokensEqual, jsonRequired, missingCsrfToken } from "../apps/api/src/security/csrf.js";
import { migrate } from "../apps/api/src/storage/db.js";
import { apiTokens, users } from "../apps/api/src/storage/repositories.js";
import { organization } from "./support/fixtures.js";
import { readCookies, serve } from "./support/http.js";

/* Changing requests of the API: with the session cookie they carry the
   session's CSRF token, with an API token they need none, and without a
   session they are accepted as JSON only. */

migrate();

const app = express();
// Both body parsers, like the server, so a form body would reach the routes if the check let it through.
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(readCookies);
app.use(configurePassport());
app.use(attachSession);
app.use("/api", apiRoutes);
const client = await serve(app);
const { base, call } = client;

afterAll(async () => {
  await client.close();
  removeDatabase();
});

const alpha = organization("Csrf");
// A password made up for this run; a low bcrypt cost keeps the test fast.
const password = randomUUID();
const member = users.create(`signin-${randomUUID().slice(0, 8)}@example.com`, bcrypt.hashSync(password, 4), "viewer");

const send = (method: string, route: string, headers: Record<string, string>, body?: string) =>
  fetch(`${base}${route}`, { method, headers, body, redirect: "manual" });

describe("requests with the session cookie", () => {
  const cookie = { cookie: `crtwatch_session=${alpha.session.token}`, "x-tenant-id": alpha.tenant.id };

  it("are refused without the token of the session or with another one", async () => {
    const missing = await send("POST", "/api/tenants", { ...cookie, "content-type": "application/json" }, JSON.stringify({ name: "Without token" }));
    const wrong = await send("POST", "/api/tenants", { ...cookie, "content-type": "application/json", "x-csrf-token": `${alpha.session.csrfToken}x` }, JSON.stringify({ name: "Wrong token" }));
    const form = await send("POST", "/api/tenants", { ...cookie, "content-type": "application/x-www-form-urlencoded" }, "name=From+a+form");
    for (const response of [missing, wrong, form]) {
      expect(response.status).toBe(403);
      expect((await response.json()).error).toBe(missingCsrfToken);
    }
  });

  it("go through with the token of the session", async () => {
    const created = await call("POST", "/api/tenants", { name: "With token" }, { session: alpha.session, tenantId: alpha.tenant.id });
    expect(created.status).toBe(201);
  });

  it("read without a token, and /api/auth/me hands the token to the web interface", async () => {
    const me = await send("GET", "/api/auth/me", cookie);
    expect(me.status).toBe(200);
    expect((await me.json()).csrfToken).toBe(alpha.session.csrfToken);
  });
});

describe("requests with an API token", () => {
  it("need no CSRF token", async () => {
    const plain = createPlainApiToken();
    apiTokens.create("ci", hashToken(plain), ["read", "write"], alpha.owner.id);
    const created = await send("POST", "/api/tenants", { authorization: `Bearer ${plain}`, "content-type": "application/json" }, JSON.stringify({ name: "From a script" }));
    expect(created.status).toBe(201);
  });
});

describe("requests without a session", () => {
  it("sign in with JSON", async () => {
    const response = await send("POST", "/api/auth/login", { "content-type": "application/json" }, JSON.stringify({ email: member.email, password }));
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toMatch(/^crtwatch_session=/);
  });

  it("are refused as a form or as text, before anything signs in", async () => {
    const form = await send("POST", "/api/auth/login", { "content-type": "application/x-www-form-urlencoded" }, new URLSearchParams({ email: member.email, password }).toString());
    const multipart = new FormData();
    multipart.set("email", member.email);
    multipart.set("password", password);
    const upload = await fetch(`${base}/api/auth/login`, { method: "POST", body: multipart });
    const text = await send("POST", "/api/auth/login", { "content-type": "text/plain" }, JSON.stringify({ email: member.email, password }));
    for (const response of [form, upload, text]) {
      expect(response.status).toBe(415);
      expect(response.headers.get("set-cookie")).toBeNull();
      expect((await response.json()).error).toBe(jsonRequired);
    }
  });

  it("without a body reach their route, which answers them", async () => {
    const logout = await send("POST", "/api/auth/logout", {});
    expect(logout.status).toBe(401);
    expect((await logout.json()).error).toMatch(/^Sign in to continue/);
  });
});

describe("CSRF token comparison", () => {
  it("matches equal tokens only and never an empty one", () => {
    expect(csrfTokensEqual("abc123", "abc123")).toBe(true);
    expect(csrfTokensEqual("abc123", "abc124")).toBe(false);
    expect(csrfTokensEqual("abc123", "abc1234")).toBe(false);
    expect(csrfTokensEqual("", "")).toBe(false);
    expect(csrfTokensEqual(undefined, "abc123")).toBe(false);
    expect(csrfTokensEqual("abc123", undefined)).toBe(false);
  });
});

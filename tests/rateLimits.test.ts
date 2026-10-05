import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { createMfaChallenge } from "../apps/api/src/auth/tokens.js";
import { createAuthLimiter, createMfaAccountLimiter, createRequestLimiter } from "../apps/api/src/security/rateLimits.js";

const servers: Server[] = [];

// trust proxy lets each request name its client address in X-Forwarded-For.
const appWithProxy = () => {
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  return app;
};

const serve = (app: express.Express) =>
  new Promise<string>((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`));
    servers.push(server);
  });

const get = async (url: string, ip: string, accept = "application/json") => {
  const response = await fetch(url, { headers: { "x-forwarded-for": ip, accept } });
  return { status: response.status, retryAfter: response.headers.get("retry-after"), type: response.headers.get("content-type") ?? "", body: await response.text() };
};

const post = async (url: string, body: unknown, ip: string) => {
  const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": ip }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.text() };
};

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  })));
});

describe("general request limit", () => {
  it("turns a client away after the configured number of requests", async () => {
    const app = appWithProxy();
    app.use(createRequestLimiter({ windowSeconds: 60, maxRequests: 3 }));
    app.get("/api/status", (_req, res) => res.json({ ok: true }));
    const base = await serve(app);

    const statuses: number[] = [];
    for (let attempt = 0; attempt < 3; attempt += 1) statuses.push((await get(`${base}/api/status`, "203.0.113.20")).status);
    const limited = await get(`${base}/api/status`, "203.0.113.20");

    expect(statuses).toEqual([200, 200, 200]);
    expect(limited.status).toBe(429);
    expect(limited.retryAfter).toMatch(/^\d+$/);
    expect(JSON.parse(limited.body).error).toMatch(/^Too many requests from your address: the limit is 3 requests in 60 seconds\. Wait \d+ seconds and try again\.$/);
    expect((await get(`${base}/api/status`, "203.0.113.21")).status).toBe(200);
  });

  it("answers a browser that navigated to a page in plain text", async () => {
    const app = appWithProxy();
    app.use(createRequestLimiter({ windowSeconds: 30, maxRequests: 1 }));
    app.get("/public/status/mail.html", (_req, res) => res.send("<p>ok</p>"));
    const base = await serve(app);

    await get(`${base}/public/status/mail.html`, "203.0.113.30", "text/html");
    const limited = await get(`${base}/public/status/mail.html`, "203.0.113.30", "text/html");

    expect(limited.status).toBe(429);
    expect(limited.type).toMatch(/^text\/plain/);
    expect(limited.body).toMatch(/limit is 1 requests in 30 seconds/);
  });

  it("is switched off with a limit of 0", async () => {
    const app = appWithProxy();
    app.use(createRequestLimiter({ windowSeconds: 60, maxRequests: 0 }));
    app.get("/api/status", (_req, res) => res.json({ ok: true }));
    const base = await serve(app);

    for (let attempt = 0; attempt < 5; attempt += 1) expect((await get(`${base}/api/status`, "203.0.113.40")).status).toBe(200);
  });
});

describe("sign-in attempt limit", () => {
  it("counts only failed attempts per client address", async () => {
    const app = appWithProxy();
    app.post("/api/auth/login", createAuthLimiter({ windowMinutes: 15, maxAttempts: 2 }), (req, res) =>
      req.body.password === "right" ? res.json({ ok: true }) : res.status(401).json({ error: "Invalid email or password." }));
    const base = await serve(app);
    const login = (password: string, ip = "198.51.100.10") => post(`${base}/api/auth/login`, { password }, ip);

    for (let attempt = 0; attempt < 3; attempt += 1) expect((await login("right")).status).toBe(200);
    expect((await login("wrong")).status).toBe(401);
    expect((await login("wrong")).status).toBe(401);
    const limited = await login("right");

    expect(limited.status).toBe(429);
    expect(JSON.parse(limited.body).error).toMatch(/^Too many failed attempts from your address: at most 2 are allowed in 15 minutes\. Wait 15 minutes and try again\.$/);
    expect((await login("right", "198.51.100.11")).status).toBe(200);
  });

  it("counts two-factor codes per account, whatever address they come from", async () => {
    const app = appWithProxy();
    app.post("/api/auth/mfa/verify-login", createMfaAccountLimiter({ windowMinutes: 5, maxAttempts: 2 }), (_req, res) => res.status(401).json({ error: "The code is not valid." }));
    const base = await serve(app);
    const verify = (mfaToken: string, ip: string) => post(`${base}/api/auth/mfa/verify-login`, { mfaToken, code: "000000" }, ip);
    const attacked = createMfaChallenge("account-a");

    expect((await verify(attacked, "192.0.2.1")).status).toBe(401);
    expect((await verify(attacked, "192.0.2.2")).status).toBe(401);
    const limited = await verify(attacked, "192.0.2.3");

    expect(limited.status).toBe(429);
    expect(JSON.parse(limited.body).error).toMatch(/for this account: at most 2 are allowed in 5 minutes/);
    expect((await verify(createMfaChallenge("account-b"), "192.0.2.3")).status).toBe(401);
  });
});

import fs from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import express from "express";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

/* Route-level checks with the storage layer replaced, so no database is opened:
   who may touch backup files, what /mfa/setup does on an active second factor,
   that sign-in attempts are limited, and how a failed channel test is answered. */

const mocks = vi.hoisted(() => {
  const fn = <T>(value?: T) => vi.fn(() => value as T);
  return {
    repositories: {
      users: {
        count: fn(1), findByEmail: fn(undefined), findById: fn(undefined), create: fn(undefined), update: fn(undefined),
        setPendingMfaSecret: fn(undefined), getMfaSecret: fn(null), enableMfa: fn(undefined), disableMfa: fn(undefined), consumeMfaBackupCode: fn(false)
      },
      sessions: { create: fn(undefined), find: fn(undefined), delete: fn(undefined) },
      tenants: { forUser: fn([]), create: fn(undefined), get: fn(undefined), members: fn([]) },
      teams: { listForUser: fn([]) },
      teamMemberships: { activeForUser: fn([]) },
      tenantInvites: { findByToken: fn(undefined), accept: fn(undefined) },
      apiTokens: { findByHash: fn(undefined), markUsed: fn(undefined), list: fn([]) },
      appSettings: { platform: fn({ publicRegistrationEnabled: true }), backups: fn({ enabled: false, intervalHours: 24, keep: 7 }), set: fn(undefined) },
      channels: { get: fn(undefined) },
      alerts: {}, auditLogs: {}, deliveries: {}, incidents: {}, monitors: {}, results: {}, subscriptions: {}, userAlerts: {}
    },
    backups: {
      listBackups: fn([{ name: "crtwatch-20261001-120000.sqlite", size: 2048, createdAt: "2026-10-01T12:00:00.000Z", automatic: false }]),
      createBackup: fn({ name: "crtwatch-20261001-120500.sqlite" }),
      deleteBackup: fn(undefined),
      findBackupPath: vi.fn((_name: string): string | null => null)
    },
    service: { testChannel: vi.fn(async (_channel: unknown) => undefined) }
  };
});

vi.mock("../apps/api/src/storage/repositories.js", () => mocks.repositories);
vi.mock("../apps/api/src/backup/backupService.js", () => mocks.backups);
vi.mock("../apps/api/src/notifications/service.js", () => mocks.service);

import { configurePassport } from "../apps/api/src/auth/passport.js";
import { env } from "../apps/api/src/config/env.js";
import { NotificationTargetError } from "../apps/api/src/notifications/delivery.js";
import { authRoutes } from "../apps/api/src/routes/authRoutes.js";
import { opsRoutes } from "../apps/api/src/routes/opsRoutes.js";
import { systemRoutes } from "../apps/api/src/routes/systemRoutes.js";
import { authLimiter } from "../apps/api/src/security/rateLimits.js";

type FakeSession = { user: Record<string, unknown>; tenantRole: string } | null;
let session: FakeSession = null;

const app = express();
app.use(express.json());
app.use(configurePassport());
app.use((req, _res, next) => {
  if (session) {
    req.user = session.user as Express.User;
    req.csrfToken = "csrf-token";
    req.currentTenant = { id: "tenant-1" } as Express.Request["currentTenant"];
    req.tenantRole = session.tenantRole as Express.Request["tenantRole"];
  }
  next();
});
app.use("/api/auth", authRoutes);
app.use("/api", opsRoutes);
app.use("/api", systemRoutes);

const server: Server = await new Promise((resolve) => {
  const started = app.listen(0, "127.0.0.1", () => resolve(started));
});
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

const call = async (method: string, route: string, body?: unknown) => {
  const response = await fetch(`${base}${route}`, {
    method,
    headers: { "content-type": "application/json", "x-csrf-token": "csrf-token" },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await response.text();
  return { status: response.status, text, json: () => JSON.parse(text) };
};

const tenantOwner = { user: { id: "u-owner", email: "owner@example.com", role: "viewer", mfaEnabled: false }, tenantRole: "owner" };
const platformAdmin = { user: { id: "u-admin", email: "admin@example.com", role: "super_admin", mfaEnabled: false }, tenantRole: "owner" };

const tempFiles: string[] = [];

beforeEach(async () => {
  session = null;
  vi.clearAllMocks();
  await authLimiter.resetKey("127.0.0.1");
});

afterAll(async () => {
  for (const file of tempFiles) fs.rmSync(file, { force: true });
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("backup files", () => {
  it("are out of reach for an organization owner without a platform role", async () => {
    session = tenantOwner;
    const responses = await Promise.all([
      call("GET", "/api/backups"),
      call("GET", "/api/backups/crtwatch-20261001-120000.sqlite"),
      call("DELETE", "/api/backups/crtwatch-20261001-120000.sqlite"),
      call("POST", "/api/backups/run", {})
    ]);

    expect(responses.map((response) => response.status)).toEqual([403, 403, 403, 403]);
    expect(responses[0].json().error).toMatch(/Only platform administrators can do this/);
    expect(mocks.backups.listBackups).not.toHaveBeenCalled();
    expect(mocks.backups.findBackupPath).not.toHaveBeenCalled();
    expect(mocks.backups.deleteBackup).not.toHaveBeenCalled();
    expect(mocks.backups.createBackup).not.toHaveBeenCalled();
  });

  it("can be listed, downloaded, created and deleted by a platform administrator", async () => {
    session = platformAdmin;
    const file = path.join(os.tmpdir(), `crtwatch-test-${process.pid}.sqlite`);
    fs.writeFileSync(file, "sqlite-bytes");
    tempFiles.push(file);
    mocks.backups.findBackupPath.mockImplementation((name: string) => (name === "crtwatch-20261001-120000.sqlite" ? file : null));

    const list = await call("GET", "/api/backups");
    const download = await call("GET", "/api/backups/crtwatch-20261001-120000.sqlite");
    const created = await call("POST", "/api/backups/run", {});
    const deleted = await call("DELETE", "/api/backups/crtwatch-20261001-120000.sqlite");

    expect(list.status).toBe(200);
    expect(list.json()[0].name).toBe("crtwatch-20261001-120000.sqlite");
    expect(download).toMatchObject({ status: 200, text: "sqlite-bytes" });
    expect(created.status).toBe(201);
    expect(deleted.status).toBe(204);
    expect(mocks.backups.deleteBackup).toHaveBeenCalledWith("crtwatch-20261001-120000.sqlite");
  });

  it("answers an unknown or malformed name with 404 and a readable reason", async () => {
    session = platformAdmin;
    const missing = await call("GET", "/api/backups/crtwatch-20200101-000000.sqlite");
    const malformed = await call("DELETE", "/api/backups/..%2Fcrtwatch.sqlite");

    expect(missing.status).toBe(404);
    expect(missing.json().error).toMatch(/^Backup not found\. Reload the list/);
    expect(malformed.status).toBe(404);
    expect(mocks.backups.deleteBackup).not.toHaveBeenCalled();
  });
});

describe("two-factor setup", () => {
  it("does not replace an active second factor", async () => {
    session = { ...tenantOwner, user: { ...tenantOwner.user, mfaEnabled: true } };
    const response = await call("POST", "/api/auth/mfa/setup", {});

    expect(response.status).toBe(409);
    expect(response.json().error).toMatch(/already active.*disable it with your current password/);
    expect(mocks.repositories.users.setPendingMfaSecret).not.toHaveBeenCalled();
  });

  it("starts a setup while no second factor is active", async () => {
    session = tenantOwner;
    const response = await call("POST", "/api/auth/mfa/setup", {});

    expect(response.status).toBe(200);
    expect(response.json().secret).toMatch(/^[A-Z2-7]+$/);
    expect(mocks.repositories.users.setPendingMfaSecret).toHaveBeenCalledTimes(1);
  });
});

describe("sign-in", () => {
  it("stops answering a client after too many failed attempts", async () => {
    const statuses: number[] = [];
    for (let attempt = 0; attempt <= env.authRateLimitMaxAttempts; attempt += 1) {
      statuses.push((await call("POST", "/api/auth/login", { email: "nobody@example.com", password: "guess" })).status);
    }

    expect(statuses.slice(0, -1).every((status) => status === 401)).toBe(true);
    expect(statuses.at(-1)).toBe(429);
  });
});

describe("channel test", () => {
  const channel = { name: "Ops hook", type: "webhook", config: { url: "http://10.0.0.5/hook" } };

  it("reports a refused target as a client error with the reason", async () => {
    session = platformAdmin;
    mocks.service.testChannel.mockRejectedValueOnce(new NotificationTargetError("Notification target 10.0.0.5 is a private, loopback or link-local address."));
    const response = await call("POST", "/api/notification-channels/test", channel);

    expect(response.status).toBe(400);
    expect(response.json().error).toMatch(/^Notification target 10\.0\.0\.5 is a private/);
  });

  it("reports a failed delivery as a gateway error instead of crashing the server", async () => {
    session = platformAdmin;
    mocks.service.testChannel.mockRejectedValueOnce(new Error("Notification endpoint hooks.example.com answered with HTTP 500. Check the URL and the credentials of this channel."));
    const failed = await call("POST", "/api/notification-channels/test", channel);
    const next = await call("POST", "/api/notification-channels/test", channel);

    expect(failed.status).toBe(502);
    expect(failed.json().error).toMatch(/answered with HTTP 500/);
    expect(next).toMatchObject({ status: 200, text: "{\"ok\":true}" });
  });
});

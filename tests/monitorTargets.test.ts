import { removeDatabase } from "./support/isolatedDatabase.js";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import express from "express";
import { Server as SshServer } from "ssh2";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/* Monitors reach public addresses only, unless the operator opens a network:
   saving a monitor, the check before connecting, every connection a check
   opens and every redirect of an HTTP check apply the same policy. */

type Answer = Array<{ address: string; family: number }>;
const resolver = vi.hoisted(() => ({ answers: new Map<string, Answer[]>() }));
vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns")>();
  const lookup = ((hostname: string, options: any, callback: any) => {
    const queue = resolver.answers.get(hostname);
    if (!queue?.length) return actual.lookup(hostname, options, callback);
    // Each lookup takes the next answer and the last one stays, so a name can change between two lookups.
    const answer = queue.length > 1 ? queue.shift()! : queue[0];
    if (options?.all) return callback(null, answer);
    return callback(null, answer[0].address, answer[0].family);
  }) as typeof actual.lookup;
  return { ...actual, default: { ...actual, lookup }, lookup };
});

import { attachSession } from "../apps/api/src/auth/auth.js";
import { requestMonitorUrl, type MonitorHttpSettings } from "../apps/api/src/checks/httpTarget.js";
import { runServiceCheck } from "../apps/api/src/checks/serviceChecker.js";
import { runTlsCheck } from "../apps/api/src/checks/tlsChecker.js";
import { assertAllowedTarget, MonitorTargetError, validateHost } from "../apps/api/src/checks/validation.js";
import { env } from "../apps/api/src/config/env.js";
import { apiRoutes } from "../apps/api/src/routes/index.js";
import { monitorInputSchema } from "../apps/api/src/routes/monitorSchemas.js";
import { migrate } from "../apps/api/src/storage/db.js";
import type { Monitor } from "../apps/api/src/types.js";
import { parseNetworkList } from "../apps/api/src/utils/networks.js";
import { organization } from "./support/fixtures.js";
import { readCookies, serve } from "./support/http.js";

const answer = (...addresses: string[]): Answer => addresses.map((address) => ({ address, family: net.isIP(address) }));
// Service credentials for the login checks, made up for this run.
const login = { username: `user-${randomUUID().slice(0, 8)}`, password: randomUUID() };
const refusal = /points to a private, loopback or link-local address.*MONITOR_ALLOWED_NETWORKS or ALLOW_PRIVATE_TARGETS/;

const defaults = { allowPrivateTargets: env.allowPrivateTargets, monitorAllowedNetworks: env.monitorAllowedNetworks, monitorHttpBodyLimitKb: env.monitorHttpBodyLimitKb };
const allowLoopback = () => {
  env.monitorAllowedNetworks = parseNetworkList("127.0.0.1", "MONITOR_ALLOWED_NETWORKS");
};

const closers: Array<() => Promise<void>> = [];

beforeEach(() => {
  resolver.answers.clear();
  Object.assign(env, defaults);
});

afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()));
  Object.assign(env, defaults);
});

const listen = (server: net.Server) => new Promise<number>((resolve) => {
  closers.push(() => new Promise<void>((done) => {
    if ("closeAllConnections" in server) (server as http.Server).closeAllConnections();
    server.close(() => done());
  }));
  server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
});

/** A TCP service that counts the connections it receives. */
const tcpService = async (greeting = "") => {
  let connections = 0;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    connections += 1;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    if (greeting) socket.write(greeting);
  });
  closers.push(async () => {
    for (const socket of sockets) socket.destroy();
  });
  const port = await listen(server);
  return { port, connections: () => connections };
};

const httpService = async (respond: http.RequestListener) => {
  const received: http.IncomingMessage[] = [];
  const server = http.createServer((req, res) => {
    received.push(req);
    respond(req, res);
  });
  const port = await listen(server);
  return { port, received };
};

const monitor = (partial: Partial<Monitor>): Monitor => ({
  id: "monitor-1",
  tenantId: "tenant-1",
  name: "Target",
  host: "127.0.0.1",
  port: 443,
  type: "tcp",
  enabled: true,
  intervalSeconds: 60,
  timeoutSeconds: 2,
  warningDays: 30,
  criticalDays: 7,
  gracePeriodSeconds: 0,
  sniEnabled: true,
  sniHost: null,
  validateCertificate: true,
  allowSelfSigned: false,
  tags: [],
  notificationChannelIds: [],
  notificationRecipients: {},
  config: {},
  lastStatus: "UNKNOWN",
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  ...partial
});

const httpSettings = (overrides: Partial<MonitorHttpSettings> = {}): MonitorHttpSettings => ({
  allowPrivateTargets: false,
  allowedNetworks: parseNetworkList("127.0.0.1", "MONITOR_ALLOWED_NETWORKS"),
  maxRedirects: 20,
  timeoutMs: 2000,
  bodyLimitBytes: 1024 * 1024,
  ...overrides
});

const get = (url: string, extra: { readBody?: boolean; followRedirects?: boolean; headers?: Record<string, string> } = {}) =>
  ({ url, method: "GET" as const, headers: extra.headers ?? {}, followRedirects: extra.followRedirects ?? true, readBody: extra.readBody ?? false });

describe("saving a monitor", () => {
  it("refuses private, loopback, link-local and reserved addresses", () => {
    for (const host of ["127.0.0.1", "10.0.0.5", "172.17.0.1", "192.168.1.1", "169.254.169.254", "100.64.1.1", "0.0.0.0"]) {
      expect(() => validateHost(host), host).toThrow(MonitorTargetError);
    }
    expect(() => validateHost("10.0.0.5")).toThrow(refusal);
    expect(validateHost("8.8.8.8")).toBe("8.8.8.8");
    expect(validateHost("https://Mail.Example.COM/path")).toBe("mail.example.com");
  });

  it("opens the networks the operator lists, and every address with ALLOW_PRIVATE_TARGETS", () => {
    env.monitorAllowedNetworks = parseNetworkList("10.20.0.0/16, 192.168.7.5", "MONITOR_ALLOWED_NETWORKS");
    expect(validateHost("10.20.30.40")).toBe("10.20.30.40");
    expect(validateHost("192.168.7.5")).toBe("192.168.7.5");
    expect(() => validateHost("10.21.0.1")).toThrow(MonitorTargetError);
    expect(() => validateHost("192.168.7.6")).toThrow(MonitorTargetError);
    env.allowPrivateTargets = true;
    expect(validateHost("127.0.0.1")).toBe("127.0.0.1");
  });

  it("reports a refused host or port as a validation issue", () => {
    const input = { name: "Mail", host: "10.0.0.5", port: 993, type: "imaps" };
    const refused = monitorInputSchema.safeParse(input);
    const malformed = monitorInputSchema.safeParse({ ...input, host: "mail server" });
    const badPort = monitorInputSchema.safeParse({ ...input, host: "mail.example.com", port: 70000 });
    expect(refused.success).toBe(false);
    expect(refused.error?.issues[0].message).toMatch(refusal);
    expect(malformed.error?.issues[0].message).toMatch(/valid hostname or IP address/);
    expect(badPort.error?.issues[0].message).toBe("Port must be between 1 and 65535.");
    expect(monitorInputSchema.safeParse({ ...input, host: "mail.example.com" }).success).toBe(true);
  });
});

describe("before a check connects", () => {
  it("checks an address directly and a name on every address it resolves to", async () => {
    resolver.answers.set("public.monitor.test", [answer("8.8.8.8", "2606:4700:4700::1111")]);
    resolver.answers.set("mixed.monitor.test", [answer("8.8.8.8", "127.0.0.1")]);
    resolver.answers.set("mapped.monitor.test", [answer("::ffff:169.254.169.254")]);
    resolver.answers.set("tunnel.monitor.test", [answer("2002:a00:1::1")]);
    await expect(assertAllowedTarget("public.monitor.test")).resolves.toBeUndefined();
    await expect(assertAllowedTarget("8.8.8.8")).resolves.toBeUndefined();
    for (const host of ["mixed.monitor.test", "mapped.monitor.test", "tunnel.monitor.test", "127.0.0.1", "[::1]"]) {
      await expect(assertAllowedTarget(host), host).rejects.toBeInstanceOf(MonitorTargetError);
    }
  });

  it("checks the IP address of a saved monitor again before every check", async () => {
    const service = await tcpService();
    const tls = await runTlsCheck(monitor({ type: "https", host: "127.0.0.1", port: service.port }));
    const tcp = await runServiceCheck(monitor({ type: "tcp", host: "127.0.0.1", port: service.port }));
    expect(tls.status).toBe("DOWN");
    expect(tls.problems[0]).toMatch(refusal);
    expect(tcp.message).toMatch(refusal);
    expect(service.connections()).toBe(0);
  });
});

describe("every connection of a check", () => {
  // A name whose next lookup gives a different address than the check before connecting.
  const changingName = (name: string) => resolver.answers.set(name, [answer("8.8.8.8"), answer("127.0.0.1")]);

  it("checks the address it connects to, for TCP, banner, TLS and STARTTLS checks", async () => {
    const service = await tcpService("SSH-2.0-OpenSSH_9.6\r\n");
    for (const [type, name] of [["tcp", "tcp.changing.test"], ["ssh", "ssh.changing.test"], ["https", "tls.changing.test"], ["smtp_starttls", "starttls.changing.test"]] as const) {
      changingName(name);
      const result = type === "https" || type === "smtp_starttls"
        ? await runTlsCheck(monitor({ type, host: name, port: service.port }))
        : await runServiceCheck(monitor({ type, host: name, port: service.port }));
      expect(result.status, type).toBe("DOWN");
      expect(result.problems[0], type).toMatch(refusal);
    }
    expect(service.connections()).toBe(0);
  });

  it("logs in to SSH over the checked connection", async () => {
    allowLoopback();
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
    const logins: string[] = [];
    const connections = new Set<{ end: () => void }>();
    closers.push(async () => {
      for (const connection of connections) connection.end();
    });
    const server = new SshServer({ hostKeys: [privateKey] }, (client) => {
      connections.add(client);
      client.on("close", () => connections.delete(client));
      client.on("authentication", (context) => {
        if (context.method === "password" && context.username === login.username && context.password === login.password) {
          logins.push(context.username);
          return context.accept();
        }
        context.reject(["password"]);
      });
      client.on("error", () => undefined);
    });
    const port = await listen(server as unknown as net.Server);
    const sshMonitor = (host: string, password: string) => monitor({ type: "ssh", host, port, config: { loginEnabled: true, username: login.username, password } });

    const ok = await runServiceCheck(sshMonitor("127.0.0.1", login.password));
    const wrongPassword = await runServiceCheck(sshMonitor("127.0.0.1", `${login.password}-other`));
    env.monitorAllowedNetworks = [];
    changingName("ssh-login.changing.test");
    const refused = await runServiceCheck(sshMonitor("ssh-login.changing.test", login.password));

    expect(ok.status).toBe("OK");
    expect(ok.message).toBe("SSH login succeeded.");
    expect(wrongPassword.status).toBe("DOWN");
    expect(refused.status).toBe("DOWN");
    expect(refused.message).toMatch(refusal);
    expect(logins).toEqual([login.username]);
  });
});

describe("HTTP checks", () => {
  it("check every redirect target against the policy before connecting", async () => {
    resolver.answers.set("linklocal.monitor.test", [answer("169.254.169.254")]);
    const service = await httpService((req, res) => {
      if (req.url === "/literal") return res.writeHead(302, { location: "http://10.0.0.1/status" }).end();
      if (req.url === "/named") return res.writeHead(302, { location: "http://linklocal.monitor.test/status" }).end();
      if (req.url === "/scheme") return res.writeHead(302, { location: "file:///etc/passwd" }).end();
      res.end("ok");
    });
    const base = `http://127.0.0.1:${service.port}`;
    await expect(requestMonitorUrl(get(`${base}/literal`), httpSettings())).rejects.toThrow(refusal);
    await expect(requestMonitorUrl(get(`${base}/named`), httpSettings())).rejects.toBeInstanceOf(MonitorTargetError);
    await expect(requestMonitorUrl(get(`${base}/scheme`), httpSettings())).rejects.toThrow(/scheme "file", which crt.watch does not follow/);
    const manual = await requestMonitorUrl(get(`${base}/literal`, { followRedirects: false }), httpSettings());
    expect(manual.status).toBe(302);
  });

  it("follow redirects up to the operator's limit", async () => {
    const service = await httpService((req, res) => {
      const hop = Number(req.url?.slice(1) || 0);
      if (hop < 3) return res.writeHead(302, { location: `/${hop + 1}` }).end();
      res.end("arrived");
    });
    const base = `http://127.0.0.1:${service.port}`;
    const followed = await requestMonitorUrl(get(`${base}/0`, { readBody: true }), httpSettings({ maxRedirects: 3 }));
    expect(followed).toMatchObject({ status: 200, body: "arrived", url: `${base}/3` });
    await expect(requestMonitorUrl(get(`${base}/0`), httpSettings({ maxRedirects: 2 }))).rejects.toThrow(/redirected more than 2 times.*MONITOR_MAX_REDIRECTS/);
  });

  it("read the body up to the limit and name the limit when the expected text lies beyond it", async () => {
    allowLoopback();
    const service = await httpService((_req, res) => res.end(`${"a".repeat(4096)}needle`));
    const url = `http://127.0.0.1:${service.port}/`;
    const cut = await requestMonitorUrl(get(url, { readBody: true }), httpSettings({ bodyLimitBytes: 1024 }));
    const whole = await requestMonitorUrl(get(url, { readBody: true }), httpSettings({ bodyLimitBytes: 8192 }));
    expect(cut).toMatchObject({ bodyTruncated: true });
    expect(cut.body).toHaveLength(1024);
    expect(whole).toMatchObject({ bodyTruncated: false, body: `${"a".repeat(4096)}needle` });

    const check = monitor({ type: "http", host: "127.0.0.1", port: service.port, config: { scheme: "http", expectedText: "needle" } });
    env.monitorHttpBodyLimitKb = 1;
    const limited = await runServiceCheck(check);
    env.monitorHttpBodyLimitKb = 8;
    const found = await runServiceCheck(check);
    expect(limited.status).toBe("DOWN");
    expect(limited.message).toMatch(/expected text within its first 1 KB.*MONITOR_HTTP_BODY_LIMIT_KB/);
    expect(found.status).toBe("OK");
  });

  it("keep the monitor's timeout for the whole exchange, body included", async () => {
    const service = await httpService((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      const drip = setInterval(() => res.write("."), 50);
      res.on("close", () => clearInterval(drip));
    });
    await expect(requestMonitorUrl(get(`http://127.0.0.1:${service.port}/`, { readBody: true }), httpSettings({ timeoutMs: 400 }))).rejects.toThrow(/did not answer within 0.4 seconds/);
  });

  it("send basic authentication to the configured origin only", async () => {
    allowLoopback();
    const landing = await httpService((_req, res) => res.end("welcome"));
    const start = await httpService((_req, res) => res.writeHead(302, { location: `http://127.0.0.1:${landing.port}/home` }).end());
    const result = await runServiceCheck(monitor({ type: "http_login", host: "127.0.0.1", port: start.port, config: { scheme: "http", authType: "basic", username: login.username, password: login.password, expectedText: "welcome" } }));
    expect(result.status).toBe("OK");
    expect(start.received[0].headers.authorization).toBe(`Basic ${Buffer.from(`${login.username}:${login.password}`).toString("base64")}`);
    expect(landing.received[0].headers.authorization).toBeUndefined();
  });

  it("post a login form once and report its redirect as the answer", async () => {
    allowLoopback();
    const bodies: string[] = [];
    const service = await httpService((req, res) => {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        bodies.push(body);
        res.writeHead(302, { location: "/dashboard" }).end();
      });
    });
    const result = await runServiceCheck(monitor({ type: "http_login", host: "127.0.0.1", port: service.port, config: { scheme: "http", username: login.username, password: login.password, usernameField: "user", passwordField: "pass", expectedStatus: 302 } }));
    expect(result.status).toBe("OK");
    expect(bodies).toEqual([new URLSearchParams({ user: login.username, pass: login.password }).toString()]);
    expect(service.received[0].method).toBe("POST");
  });
});

describe("the monitor API", () => {
  migrate();
  const app = express();
  app.use(express.json());
  app.use(readCookies);
  app.use(attachSession);
  app.use("/api", apiRoutes);
  const owner = organization("Targets");
  let client: Awaited<ReturnType<typeof serve>>;

  afterAll(async () => {
    await client?.close();
    removeDatabase();
  });

  it("answers a refused host with 400 and the reason, and keeps serving", async () => {
    client = await serve(app);
    const options = { session: owner.session, tenantId: owner.tenant.id };
    const refused = await client.call("POST", "/api/monitors", { name: "Internal", host: "10.0.0.5", port: 443, type: "https" }, options);
    const malformed = await client.call("POST", "/api/monitors", { name: "Broken", host: "not a host", port: 443, type: "https" }, options);
    const health = await client.call("GET", "/api/health");
    expect(refused.status).toBe(400);
    expect(refused.json().error).toMatch(refusal);
    expect(malformed.status).toBe(400);
    expect(health.json()).toEqual({ ok: true });
  });
});

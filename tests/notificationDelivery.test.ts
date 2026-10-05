import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { NotificationTargetError, postNotification, type DeliverySettings } from "../apps/api/src/notifications/delivery.js";
import { isPublicAddress, parseNetworkList } from "../apps/api/src/utils/networks.js";

type Received = { method?: string; url?: string; headers: http.IncomingHttpHeaders; body: string };

const servers: http.Server[] = [];

const startServer = (respond: (req: http.IncomingMessage, res: http.ServerResponse) => void) =>
  new Promise<{ port: number; received: Received[]; server: http.Server }>((resolve) => {
    const received: Received[] = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        received.push({ method: req.method, url: req.url, headers: req.headers, body });
        respond(req, res);
      });
    });
    servers.push(server);
    server.listen(0, "127.0.0.1", () => resolve({ port: (server.address() as AddressInfo).port, received, server }));
  });

const closeServer = (server: http.Server) => new Promise<void>((resolve) => {
  server.closeAllConnections();
  server.close(() => resolve());
});

const settings = (overrides: Partial<DeliverySettings> = {}): DeliverySettings => ({
  allowPrivateTargets: false,
  allowedNetworks: [],
  maxRedirects: 3,
  timeoutMs: 2000,
  ...overrides
});

// The test servers listen on 127.0.0.1, which the default policy refuses.
const loopbackListed = (overrides: Partial<DeliverySettings> = {}) =>
  settings({ allowedNetworks: parseNetworkList("127.0.0.1/32", "NOTIFICATION_ALLOWED_NETWORKS"), ...overrides });

const jsonRequest = (url: string, headers: Record<string, string> = {}) =>
  ({ url, headers, body: JSON.stringify({ ok: true }), contentType: "application/json" });

afterEach(async () => {
  await Promise.all(servers.splice(0).map(closeServer));
});

describe("notification target addresses", () => {
  it("treats private, loopback, link-local and reserved addresses as internal", () => {
    const internal = [
      "127.0.0.1", "10.1.2.3", "172.16.5.4", "172.31.255.255", "192.168.1.10", "169.254.169.254", "100.64.0.1",
      "0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "fd12:3456::1",
      "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.0.0.5", "64:ff9b::a00:1", "64:ff9b::169.254.169.254"
    ];
    for (const address of internal) expect(isPublicAddress(address), address).toBe(false);
  });

  it("treats the IPv6 forms that carry an internal IPv4 address, and the remaining special-purpose ranges, as internal", () => {
    const internal = [
      "2002:7f00:1::1", "2002:a00:5::1", "2002:a9fe:a9fe::1", "2002:c0a8:101::1", "::127.0.0.1", "::7f00:1", "::ffff:0:7f00:1",
      "2001::1", "2001:0:4136:e378::1", "2001:2::1", "2001:1ff::1", "3fff::1", "5f00::1", "100:0:0:1::1"
    ];
    for (const address of internal) expect(isPublicAddress(address), address).toBe(false);
    for (const address of ["2001:4860:4860::8888", "2a00:1450:4001::1", "2002:808:808::1", "64:ff9b::101:101"]) {
      expect(isPublicAddress(address), address).toBe(true);
    }
  });

  it("treats public addresses as public", () => {
    for (const address of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "192.169.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"]) {
      expect(isPublicAddress(address), address).toBe(true);
    }
    expect(isPublicAddress("intranet.local")).toBe(false);
  });
});

describe("notification delivery", () => {
  it("refuses a loopback address before anything is sent", async () => {
    const { port, received } = await startServer((_req, res) => res.end("ok"));
    await expect(postNotification(jsonRequest(`http://127.0.0.1:${port}/hook`), settings())).rejects.toBeInstanceOf(NotificationTargetError);
    expect(received).toHaveLength(0);
  });

  it("checks the address a host name resolves to", async () => {
    const { port, received } = await startServer((_req, res) => res.end("ok"));
    await expect(postNotification(jsonRequest(`http://localhost:${port}/hook`), settings())).rejects.toThrow(/private, loopback or link-local address/);
    expect(received).toHaveLength(0);
  });

  it("refuses the metadata endpoint, other schemes and malformed URLs with a readable reason", async () => {
    await expect(postNotification(jsonRequest("http://169.254.169.254/latest/meta-data/"), settings())).rejects.toThrow(/NOTIFICATION_ALLOWED_NETWORKS or ALLOW_PRIVATE_NOTIFICATION_TARGETS/);
    await expect(postNotification(jsonRequest("http://[::1]:9/hook"), settings())).rejects.toBeInstanceOf(NotificationTargetError);
    await expect(postNotification(jsonRequest("file:///etc/passwd"), settings())).rejects.toThrow("Notification URL must start with https:// or http://.");
    await expect(postNotification(jsonRequest("hooks example com"), settings())).rejects.toThrow(/not a valid address/);
  });

  it("delivers to internal targets once the operator allows them", async () => {
    const { port, received } = await startServer((_req, res) => res.end("ok"));
    const allPrivate = await postNotification(jsonRequest(`http://127.0.0.1:${port}/all`, { "x-channel": "test" }), settings({ allowPrivateTargets: true }));
    const listed = await postNotification(jsonRequest(`http://127.0.0.1:${port}/listed`), loopbackListed());
    expect(allPrivate).toEqual({ status: 200, host: "127.0.0.1" });
    expect(listed.status).toBe(200);
    expect(received.map((request) => request.url)).toEqual(["/all", "/listed"]);
    expect(received[0]).toMatchObject({ method: "POST", body: "{\"ok\":true}" });
    expect(received[0].headers["content-type"]).toBe("application/json");
    expect(received[0].headers["x-channel"]).toBe("test");
  });

  it("keeps other internal ranges closed when one network is listed", async () => {
    await expect(postNotification(jsonRequest("http://10.0.0.1/hook"), loopbackListed())).rejects.toBeInstanceOf(NotificationTargetError);
  });

  it("follows redirects within the limit and keeps the body on 307 and 308", async () => {
    const { port, received } = await startServer((req, res) => {
      if (req.url === "/start") return res.writeHead(307, { location: "/next" }).end();
      if (req.url === "/next") return res.writeHead(308, { location: "/final" }).end();
      res.end("ok");
    });
    const result = await postNotification(jsonRequest(`http://127.0.0.1:${port}/start`), loopbackListed({ maxRedirects: 2 }));
    expect(result.status).toBe(200);
    expect(received.map((request) => `${request.method} ${request.url} ${request.body}`)).toEqual([
      "POST /start {\"ok\":true}",
      "POST /next {\"ok\":true}",
      "POST /final {\"ok\":true}"
    ]);
  });

  it("stops after the configured number of redirects", async () => {
    const { port } = await startServer((_req, res) => res.writeHead(302, { location: "/again" }).end());
    await expect(postNotification(jsonRequest(`http://127.0.0.1:${port}/`), loopbackListed({ maxRedirects: 0 }))).rejects.toThrow(/redirected more than 0 times/);
    await expect(postNotification(jsonRequest(`http://127.0.0.1:${port}/`), loopbackListed({ maxRedirects: 2 }))).rejects.toThrow(/redirected more than 2 times.*NOTIFICATION_MAX_REDIRECTS/);
  });

  it("checks every redirect target against the policy", async () => {
    const { port } = await startServer((_req, res) => res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }).end());
    await expect(postNotification(jsonRequest(`http://127.0.0.1:${port}/`), loopbackListed())).rejects.toBeInstanceOf(NotificationTargetError);
  });

  it("drops credentials on a redirect to another origin and continues a 302 after POST as GET", async () => {
    const second = await startServer((_req, res) => res.end("ok"));
    const first = await startServer((_req, res) => res.writeHead(302, { location: `http://127.0.0.1:${second.port}/landing` }).end());
    await postNotification(jsonRequest(`http://127.0.0.1:${first.port}/`, { Authorization: "GenieKey secret" }), loopbackListed());
    expect(first.received[0].headers.authorization).toBe("GenieKey secret");
    expect(second.received[0]).toMatchObject({ method: "GET", url: "/landing", body: "" });
    expect(second.received[0].headers.authorization).toBeUndefined();
    expect(second.received[0].headers["content-type"]).toBeUndefined();
  });

  it("gives up when the endpoint does not answer in time", async () => {
    const { port } = await startServer(() => undefined);
    await expect(postNotification(jsonRequest(`http://127.0.0.1:${port}/`), loopbackListed({ timeoutMs: 300 }))).rejects.toThrow(/did not answer within 0.3 seconds/);
  });

  // Windows retries a refused loopback connection for a while before reporting it.
  it("explains a refused connection", async () => {
    const { port, server } = await startServer((_req, res) => res.end("ok"));
    await closeServer(servers.splice(servers.indexOf(server), 1)[0]);
    await expect(postNotification(jsonRequest(`http://127.0.0.1:${port}/`), loopbackListed({ timeoutMs: 8000 }))).rejects.toThrow(/refused the connection/);
  }, 15_000);
});

describe("NOTIFICATION_ALLOWED_NETWORKS", () => {
  it("reads addresses and networks separated by commas or spaces", () => {
    expect(parseNetworkList("192.168.10.5, 10.20.0.0/16 fd00::/8", "NOTIFICATION_ALLOWED_NETWORKS")).toEqual([
      { address: "192.168.10.5", prefix: 32, type: "ipv4" },
      { address: "10.20.0.0", prefix: 16, type: "ipv4" },
      { address: "fd00::", prefix: 8, type: "ipv6" }
    ]);
    expect(parseNetworkList("", "NOTIFICATION_ALLOWED_NETWORKS")).toEqual([]);
  });

  it("names the setting and the entry it cannot read", () => {
    expect(() => parseNetworkList("10.0.0.0/33", "NOTIFICATION_ALLOWED_NETWORKS")).toThrow('NOTIFICATION_ALLOWED_NETWORKS contains "10.0.0.0/33", which is neither an IP address nor a network.');
    expect(() => parseNetworkList("intranet.local", "NOTIFICATION_ALLOWED_NETWORKS")).toThrow(/"intranet.local"/);
    expect(() => parseNetworkList("10.0.0.0/", "NOTIFICATION_ALLOWED_NETWORKS")).toThrow(/"10.0.0.0\/"/);
  });
});

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { trustProxySetting, type TrustProxy } from "../apps/api/src/config/env.js";
import { describeProxyTrust, forwardedHeaderHint, reportIgnoredForwardedHeader } from "../apps/api/src/security/proxy.js";
import { createRequestLimiter } from "../apps/api/src/security/rateLimits.js";

/* Who may name the client address in X-Forwarded-For. By default nobody, and
   the client address comes from the connection. */

const servers: Server[] = [];

const serveWith = async (trust: TrustProxy, extra?: (app: express.Express) => void) => {
  const app = express();
  if (trust !== false) app.set("trust proxy", trust);
  extra?.(app);
  app.get("/ip", (req, res) => res.json({ ip: req.ip }));
  return new Promise<string>((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`));
    servers.push(server);
  });
};

const clientAddress = async (base: string, forwardedFor: string) =>
  (await (await fetch(`${base}/ip`, { headers: { "x-forwarded-for": forwardedFor } })).json()).ip as string;

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  })));
});

describe("TRUST_PROXY", () => {
  it("is off unless the operator sets it", () => {
    expect(trustProxySetting({}, "TRUST_PROXY")).toBe(false);
    expect(trustProxySetting({ TRUST_PROXY: " " }, "TRUST_PROXY")).toBe(false);
    expect(trustProxySetting({ TRUST_PROXY: "false" }, "TRUST_PROXY")).toBe(false);
    expect(trustProxySetting({ TRUST_PROXY: "0" }, "TRUST_PROXY")).toBe(false);
  });

  it("reads true, hop counts and lists of proxies", () => {
    expect(trustProxySetting({ TRUST_PROXY: "true" }, "TRUST_PROXY")).toBe(1);
    expect(trustProxySetting({ TRUST_PROXY: "2" }, "TRUST_PROXY")).toBe(2);
    expect(trustProxySetting({ TRUST_PROXY: "Loopback, uniquelocal 172.18.0.0/16,10.0.0.5 fd00::/8" }, "TRUST_PROXY")).toEqual(["loopback", "uniquelocal", "172.18.0.0/16", "10.0.0.5", "fd00::/8"]);
  });

  it("stops the start with a message that names the entry it cannot read", () => {
    expect(() => trustProxySetting({ TRUST_PROXY: "loopback, proxy.example.com" }, "TRUST_PROXY")).toThrow(
      "TRUST_PROXY must be false, true, a number of proxy hops from 1 to 10, or a list of proxy addresses and networks such as loopback, uniquelocal, 172.18.0.0/16 or 10.0.0.5, but \"proxy.example.com\" in \"loopback, proxy.example.com\" is none of these. Correct it in the environment (for example in .env) or remove it to use the default of false."
    );
    expect(() => trustProxySetting({ TRUST_PROXY: "11" }, "TRUST_PROXY")).toThrow(/"11" in "11" is none of these/);
    expect(() => trustProxySetting({ TRUST_PROXY: "10.0.0.0/33" }, "TRUST_PROXY")).toThrow(/"10\.0\.0\.0\/33"/);
  });
});

describe("client addresses", () => {
  it("come from the connection when nothing is trusted, whatever X-Forwarded-For says", async () => {
    const base = await serveWith(trustProxySetting({}, "TRUST_PROXY"));

    expect(await clientAddress(base, "198.51.100.7")).toMatch(/127\.0\.0\.1$/);
  });

  it("come from X-Forwarded-For when the request arrives from a listed proxy", async () => {
    const listed = await serveWith(trustProxySetting({ TRUST_PROXY: "loopback" }, "TRUST_PROXY"));
    const unlisted = await serveWith(trustProxySetting({ TRUST_PROXY: "10.0.0.0/8" }, "TRUST_PROXY"));
    const hops = await serveWith(trustProxySetting({ TRUST_PROXY: "true" }, "TRUST_PROXY"));

    expect(await clientAddress(listed, "198.51.100.7")).toBe("198.51.100.7");
    expect(await clientAddress(unlisted, "198.51.100.7")).toMatch(/127\.0\.0\.1$/);
    expect(await clientAddress(hops, "198.51.100.7")).toBe("198.51.100.7");
  });

  it("come from the connection for the request limit, whatever X-Forwarded-For says", async () => {
    const base = await serveWith(false, (app) => app.use(createRequestLimiter({ windowSeconds: 60, maxRequests: 2 })));
    const statuses: number[] = [];
    for (const forwardedFor of ["203.0.113.1", "203.0.113.2", "203.0.113.3"]) {
      statuses.push((await fetch(`${base}/ip`, { headers: { "x-forwarded-for": forwardedFor } })).status);
    }

    expect(statuses).toEqual([200, 200, 429]);
  });
});

describe("the log", () => {
  it("says which source of client addresses is in effect", () => {
    expect(describeProxyTrust(false)).toBe("Client addresses come from the connection; X-Forwarded-For is ignored (TRUST_PROXY=false).");
    expect(describeProxyTrust(["loopback", "172.18.0.0/16"])).toBe("Client addresses come from X-Forwarded-For when the request arrives from loopback, 172.18.0.0/16 (TRUST_PROXY).");
    expect(describeProxyTrust(1)).toMatch(/trusting 1 proxy hop from any address .*Make sure nothing but the proxy can reach crt\.watch/);
  });

  it("reports once that proxy headers arrive while TRUST_PROXY is off", async () => {
    const messages: string[] = [];
    const base = await serveWith(false, (app) => app.use(reportIgnoredForwardedHeader(false, (message) => messages.push(message))));
    await clientAddress(base, "198.51.100.7");
    await clientAddress(base, "198.51.100.8");
    const trusted = await serveWith(["loopback"], (app) => app.use(reportIgnoredForwardedHeader(["loopback"], (message) => messages.push(message))));
    await clientAddress(trusted, "198.51.100.9");

    expect(messages).toEqual([forwardedHeaderHint]);
  });
});

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { afterEach, describe, expect, it, vi } from "vitest";
import { bootConfigScript } from "../apps/api/src/render/frontPage.js";
import { securityHeaders, type SecurityHeaderSettings } from "../apps/api/src/security/headers.js";

// The front page module reads users and registration state; neither matters for the markup tested here.
vi.mock("../apps/api/src/storage/repositories.js", () => ({ users: { count: () => 1 } }));
vi.mock("../apps/api/src/routes/authRoutes.js", () => ({ publicRegistrationEnabled: () => true }));

const servers: Server[] = [];

const headersFor = async (settings: SecurityHeaderSettings) => {
  const app = express();
  app.use(securityHeaders(settings));
  app.get("/", (_req, res) => res.send("ok"));
  const base = await new Promise<string>((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`));
    servers.push(server);
  });
  return (await fetch(base)).headers;
};

const directives = (policy: string | null) =>
  Object.fromEntries((policy ?? "").split(";").map((part) => part.trim().split(/\s+/)).filter((parts) => parts[0]).map(([name, ...values]) => [name, values]));

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe("content security policy", () => {
  it("is enforced by default and only allows this server for scripts", async () => {
    const headers = await headersFor({ contentSecurityPolicy: "enforce", imageSources: ["'self'", "data:", "https:"] });
    const policy = directives(headers.get("content-security-policy"));

    expect(policy["default-src"]).toEqual(["'self'"]);
    expect(policy["script-src"]).toEqual(["'self'"]);
    expect(policy["script-src-attr"]).toEqual(["'none'"]);
    expect(policy["object-src"]).toEqual(["'none'"]);
    expect(policy["frame-ancestors"]).toEqual(["'self'"]);
    expect(policy["img-src"]).toEqual(["'self'", "data:", "https:"]);
    expect(policy).not.toHaveProperty("upgrade-insecure-requests");
    expect(headers.get("content-security-policy-report-only")).toBeNull();
  });

  it("only reports violations in report-only mode and uses the configured image sources", async () => {
    const headers = await headersFor({ contentSecurityPolicy: "report-only", imageSources: ["'self'", "https://logos.example.com"] });

    expect(headers.get("content-security-policy")).toBeNull();
    expect(directives(headers.get("content-security-policy-report-only"))["img-src"]).toEqual(["'self'", "https://logos.example.com"]);
  });
});

describe("front page boot configuration", () => {
  it("travels as a JSON data block that needs no inline script permission", () => {
    const script = bootConfigScript({ setupRequired: false, frontPageEnabled: true, publicRegistrationEnabled: true });

    expect(script).toBe('<script type="application/json" id="crtwatch-boot">{"setupRequired":false,"frontPageEnabled":true,"publicRegistrationEnabled":true}</script>');
  });

  it("cannot be closed early by a value", () => {
    const script = bootConfigScript({ setupRequired: false, frontPageEnabled: true, publicRegistrationEnabled: "</script><script>alert(1)</script>" as unknown as boolean });

    expect(script.match(/<\/script>/g)).toHaveLength(1);
    expect(JSON.parse(script.replace(/^<script[^>]*>/, "").replace(/<\/script>$/, "")).publicRegistrationEnabled).toBe("</script><script>alert(1)</script>");
  });
});

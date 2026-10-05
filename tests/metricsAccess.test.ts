import { removeDatabase } from "./support/isolatedDatabase.js";
import cookieParser from "cookie-parser";
import express from "express";
import { afterAll, describe, expect, it } from "vitest";
import { attachSession, createPlainApiToken, hashToken } from "../apps/api/src/auth/auth.js";
import { secretSetting } from "../apps/api/src/config/env.js";
import { migrate } from "../apps/api/src/storage/db.js";
import { apiTokens } from "../apps/api/src/storage/repositories.js";
import { metricsAccess, metricsHandler, type MetricsSettings } from "../apps/api/src/routes/metrics.js";
import { memberOf, monitorIn, organization } from "./support/fixtures.js";
import { serve } from "./support/http.js";

/* Who may read /metrics, and what each caller sees. */

migrate();

const operatorToken = "prometheus-scrape-token-0123456789abcdef";
const alpha = organization("Alpha");
const beta = organization("Beta");
monitorIn(alpha.tenant.id, { name: "alpha.example.com", host: "alpha.example.com" });
monitorIn(beta.tenant.id, { name: "beta.example.com", host: "beta.example.com" });
const betaReader = memberOf(beta.tenant.id, "viewer");
const betaApiToken = createPlainApiToken();
apiTokens.create("Prometheus", hashToken(betaApiToken), ["read"], betaReader.user.id);

const clients: Array<Awaited<ReturnType<typeof serve>>> = [];
const metricsApp = async (settings: MetricsSettings) => {
  const app = express();
  app.use(cookieParser());
  app.use(attachSession);
  app.get("/metrics", metricsAccess(settings), metricsHandler);
  app.get("/unguarded", metricsHandler);
  const client = await serve(app);
  clients.push(client);
  return client.call;
};

const hosts = (text: string) => [...new Set([...text.matchAll(/host="([^"]+)"/g)].map((match) => match[1]))].sort();

afterAll(async () => {
  await Promise.all(clients.map((client) => client.close()));
  removeDatabase();
});

describe("metrics with METRICS_ACCESS=authenticated", () => {
  it("answer 401 with the way in to a caller without credentials", async () => {
    const call = await metricsApp({ access: "authenticated", token: operatorToken });
    const anonymous = await call("GET", "/metrics");
    const wrongToken = await call("GET", "/metrics", undefined, { bearer: "prometheus-scrape-token-wrong-0123456789" });

    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.get("www-authenticate")).toBe("Bearer realm=\"crt.watch metrics\"");
    expect(anonymous.text).toMatch(/^\/metrics needs authorization\. Send "Authorization: Bearer <token>" with the METRICS_TOKEN/);
    expect(anonymous.text).not.toContain("example.com");
    expect(wrongToken.status).toBe(401);
  });

  it("show every organization to the operator's token, labelled by organization", async () => {
    const call = await metricsApp({ access: "authenticated", token: operatorToken });
    const response = await call("GET", "/metrics", undefined, { bearer: operatorToken });

    expect(response.status).toBe(200);
    expect(hosts(response.text)).toEqual(["alpha.example.com", "beta.example.com"]);
    expect(response.text).toContain(`organization="${alpha.tenant.slug}"`);
    expect(response.text).toContain(`organization="${beta.tenant.slug}"`);
  });

  it("show a signed-in member the own organization only", async () => {
    const call = await metricsApp({ access: "authenticated", token: operatorToken });
    const response = await call("GET", "/metrics", undefined, { session: alpha.session });

    expect(response.status).toBe(200);
    expect(hosts(response.text)).toEqual(["alpha.example.com"]);
  });

  it("show the organization of a crt.watch API token", async () => {
    const call = await metricsApp({ access: "authenticated", token: operatorToken });
    const response = await call("GET", "/metrics", undefined, { bearer: betaApiToken });

    expect(response.status).toBe(200);
    expect(hosts(response.text)).toEqual(["beta.example.com"]);
  });

  it("accept no bearer value at all while METRICS_TOKEN is unset", async () => {
    const call = await metricsApp({ access: "authenticated", token: "" });

    expect((await call("GET", "/metrics", undefined, { bearer: "anything-at-all" })).status).toBe(401);
    expect((await call("GET", "/metrics", undefined, { bearer: operatorToken })).status).toBe(401);
  });

  it("are not served by the handler alone", async () => {
    const call = await metricsApp({ access: "authenticated", token: operatorToken });

    expect((await call("GET", "/unguarded")).status).toBe(401);
  });
});

describe("metrics with METRICS_ACCESS=public", () => {
  it("answer without credentials", async () => {
    const call = await metricsApp({ access: "public", token: "" });
    const response = await call("GET", "/metrics");

    expect(response.status).toBe(200);
    expect(hosts(response.text)).toEqual(["alpha.example.com", "beta.example.com"]);
  });
});

describe("METRICS_TOKEN", () => {
  const read = (value?: string) => secretSetting({ METRICS_TOKEN: value }, "METRICS_TOKEN", 32, "let only signed-in users and API tokens read /metrics");

  it("is optional and taken as set", () => {
    expect(read(undefined)).toBe("");
    expect(read("  ")).toBe("");
    expect(read(operatorToken)).toBe(operatorToken);
  });

  it("must be long and without spaces, and the message never repeats it", () => {
    expect(() => read("short-token")).toThrow("METRICS_TOKEN must be at least 32 characters long and contain no spaces, but the value set has 11 characters. Generate one with \"openssl rand -hex 32\", or remove METRICS_TOKEN to let only signed-in users and API tokens read /metrics.");
    expect(() => read("with spaces in the middle of the long value")).toThrow(/and contains spaces/);
    try {
      read("short-token");
    } catch (error) {
      expect(String(error)).not.toContain("short-token");
    }
  });

  it("follows the minimum length it is read with", () => {
    expect(() => secretSetting({ X: "a".repeat(40) }, "X", 48, "keep the default")).toThrow(/^X must be at least 48 characters long/);
    expect(secretSetting({ X: "a".repeat(48) }, "X", 48, "keep the default")).toBe("a".repeat(48));
  });
});

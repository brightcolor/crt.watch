import http from "node:http";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { runServiceCheck } from "../apps/api/src/checks/serviceChecker.js";
import type { Monitor } from "../apps/api/src/types.js";
import { metricsHandler } from "../apps/api/src/routes/metrics.js";
import { migrate } from "../apps/api/src/storage/db.js";

const servers: Array<http.Server | net.Server> = [];

describe("service checks", () => {
  afterEach(async () => {
    await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    servers.length = 0;
  });

  it("checks HTTP status and expected text", async () => {
    const port = await startHttpServer((_req, res) => res.end("service healthy"));
    const result = await runServiceCheck(monitor({ type: "http", port, config: { scheme: "http", expectedText: "healthy" } }));

    expect(result.status).toBe("OK");
  });

  it("checks SSH service banners", async () => {
    const port = await startTcpServer((socket) => socket.write("SSH-2.0-OpenSSH_9.6\r\n"));
    const result = await runServiceCheck(monitor({ type: "ssh", port }));

    expect(result.status).toBe("OK");
  });

  it("marks unexpected service banners as down", async () => {
    const port = await startTcpServer((socket) => socket.write("not ssh\r\n"));
    const result = await runServiceCheck(monitor({ type: "ssh", port }));

    expect(result.status).toBe("DOWN");
    expect(result.problems[0]).toContain("banner was unexpected");
  });

  it("checks FTP username and password login when explicitly allowed", async () => {
    const port = await startTcpServer((socket) => {
      socket.write("220 FTP ready\r\n");
      socket.on("data", (chunk) => {
        const command = chunk.toString("utf8");
        if (/USER alice/i.test(command)) socket.write("331 Password required\r\n");
        if (/PASS secret/i.test(command)) socket.write("230 Login successful\r\n");
      });
    });
    const result = await runServiceCheck(monitor({ type: "ftp", port, config: { securityMode: "plain", loginEnabled: true, allowInsecureLogin: true, username: "alice", password: "secret" } }));

    expect(result.status).toBe("OK");
    expect(result.message).toContain("login succeeded");
  });

  it("blocks plaintext protocol login checks unless explicitly allowed", async () => {
    const port = await startTcpServer((socket) => socket.write("220 FTP ready\r\n"));
    const result = await runServiceCheck(monitor({ type: "ftp", port, config: { securityMode: "plain", loginEnabled: true, username: "alice", password: "secret" } }));

    expect(result.status).toBe("DOWN");
    expect(result.message).toContain("plaintext is disabled");
  });

  it("renders Prometheus metrics text", () => {
    migrate();
    // The access check in front of the handler decided on the operator's view of every organization.
    const response = fakeResponse();
    metricsHandler({} as any, response as any);

    expect(response.body).toContain("crtwatch_monitor_status");
    expect(response.typeValue).toContain("text/plain");
  });
});

const startHttpServer = (handler: http.RequestListener) =>
  new Promise<number>((resolve) => {
    const server = http.createServer(handler);
    servers.push(server);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (typeof address === "object" && address) resolve(address.port);
    });
  });

const startTcpServer = (handler: (socket: net.Socket) => void) =>
  new Promise<number>((resolve) => {
    const server = net.createServer(handler);
    servers.push(server);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (typeof address === "object" && address) resolve(address.port);
    });
  });

const monitor = (partial: Partial<Monitor>): Monitor => ({
  id: "monitor-1",
  name: "Local service",
  host: "127.0.0.1",
  port: 80,
  type: "http",
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

const fakeResponse = () => ({
  locals: { metricsScope: { kind: "platform" } },
  typeValue: "",
  body: "",
  type(value: string) {
    this.typeValue = value;
    return this;
  },
  send(value: string) {
    this.body = value;
    return this;
  }
});

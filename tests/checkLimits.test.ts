import net from "node:net";
import type { AddressInfo } from "node:net";
import type tls from "node:tls";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { checkLimits, ServiceConversation } from "../apps/api/src/checks/conversation.js";
import { runServiceCheck } from "../apps/api/src/checks/serviceChecker.js";
import { prepareStartTls } from "../apps/api/src/checks/starttls.js";
import { runTlsCheck } from "../apps/api/src/checks/tlsChecker.js";
import { checkTlsLogin } from "../apps/api/src/checks/tlsLogin.js";
import { probeSupportedTlsVersions } from "../apps/api/src/checks/tlsSecurity.js";
import { env } from "../apps/api/src/config/env.js";
import type { Monitor, TlsPolicySettings } from "../apps/api/src/types.js";
import { parseNetworkList } from "../apps/api/src/utils/networks.js";

/* The conversations of a check end at the read limit and at the deadline of
   the check, in addition to the idle timeout of the monitor. The tests use
   limits other than the defaults (64 KB, 60 seconds), so they finish fast. */

const defaults = {
  monitorAllowedNetworks: env.monitorAllowedNetworks,
  monitorProtocolReadLimitKb: env.monitorProtocolReadLimitKb,
  monitorCheckDeadlineSeconds: env.monitorCheckDeadlineSeconds,
  monitorTlsProbeTimeoutSeconds: env.monitorTlsProbeTimeoutSeconds
};

const servers: net.Server[] = [];
const sockets = new Set<net.Socket>();
const timers = new Set<NodeJS.Timeout>();

beforeAll(() => {
  // The test services listen on 127.0.0.1, which monitors reach once the network is allowed.
  env.monitorAllowedNetworks = parseNetworkList("127.0.0.1", "MONITOR_ALLOWED_NETWORKS");
});

afterEach(async () => {
  for (const timer of timers) clearInterval(timer);
  timers.clear();
  for (const socket of sockets) socket.destroy();
  sockets.clear();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  Object.assign(env, { ...defaults, monitorAllowedNetworks: parseNetworkList("127.0.0.1", "MONITOR_ALLOWED_NETWORKS") });
});

afterAll(() => {
  Object.assign(env, defaults);
});

/** A TCP service on 127.0.0.1; returns its port. */
const service = (onConnection: (socket: net.Socket) => void = () => {}) =>
  new Promise<number>((resolve) => {
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on("error", () => {});
      onConnection(socket);
    });
    servers.push(server);
    server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
  });

/** Writes text every intervalMs, as long as the connection is open. */
const drip = (socket: net.Socket, text: string, intervalMs = 50) => {
  const timer = setInterval(() => {
    if (!socket.destroyed) socket.write(text);
  }, intervalMs);
  timers.add(timer);
  socket.on("close", () => clearInterval(timer));
};

const connect = (port: number) => {
  const socket = net.connect({ host: "127.0.0.1", port });
  sockets.add(socket);
  return socket;
};

const monitor = (partial: Partial<Monitor>): Monitor => ({
  id: "monitor-limits",
  tenantId: "tenant-limits",
  name: "Limited service",
  host: "127.0.0.1",
  port: 1,
  type: "tcp",
  enabled: true,
  intervalSeconds: 60,
  timeoutSeconds: 2,
  warningDays: 30,
  criticalDays: 7,
  gracePeriodSeconds: 0,
  sniEnabled: false,
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

const elapsedSince = (started: number) => Date.now() - started;

describe("a conversation with a service", () => {
  it("ends when the service sends more than the read limit", async () => {
    const port = await service((socket) => socket.write("x".repeat(3000)));
    const conversation = new ServiceConversation(connect(port), "test conversation", checkLimits(1, 60), 2);

    await expect(conversation.readUntil(() => false)).rejects.toThrow(
      "The server sent more than 1 KB during the test conversation, the most a check reads. Check that the monitor uses the right port and protocol, or ask the operator of this crt.watch instance to raise MONITOR_PROTOCOL_READ_LIMIT_KB."
    );
  });

  it("ends at the deadline of the check while the service keeps sending", async () => {
    const port = await service((socket) => drip(socket, "250-still talking\r\n"));
    const started = Date.now();
    const conversation = new ServiceConversation(connect(port), "test conversation", checkLimits(64, 0.4), 2);

    await expect(conversation.readUntil(() => false)).rejects.toThrow(
      "The test conversation did not finish within the 0.4 seconds a check may take. Check that the server answers promptly, or ask the operator of this crt.watch instance to raise MONITOR_CHECK_DEADLINE_SECONDS."
    );
    expect(elapsedSince(started)).toBeLessThan(1500);
  });

  it("shares the deadline with the other connections of the check", async () => {
    const port = await service((socket) => setTimeout(() => socket.write("220 ready\r\n"), 300));
    const limits = checkLimits(64, 0.5);

    const first = new ServiceConversation(connect(port), "first conversation", limits, 2);
    await expect(first.readLine((line) => line.startsWith("220"))).resolves.toBe("220 ready");
    first.release();
    const second = new ServiceConversation(connect(port), "second conversation", limits, 2);

    await expect(second.readLine((line) => line.startsWith("220"))).rejects.toThrow("The second conversation did not finish within the 0.5 seconds a check may take.");
  });

  it("keeps the idle timeout of the monitor", async () => {
    const port = await service();
    const socket = connect(port);
    socket.setTimeout(200);
    const conversation = new ServiceConversation(socket, "test conversation", checkLimits(64, 60), 0.2);

    await expect(conversation.readUntil(() => false)).rejects.toThrow(
      "The test conversation got no answer for 0.2 seconds. Check that the service is reachable on this port, or raise the timeout of the monitor."
    );
  });

  it("reads limits from the settings", () => {
    env.monitorProtocolReadLimitKb = 3;
    env.monitorCheckDeadlineSeconds = 7;

    const limits = checkLimits();

    expect(limits).toMatchObject({ readLimitBytes: 3 * 1024, deadlineSeconds: 7 });
    expect(limits.signal.aborted).toBe(false);
  });
});

describe("the STARTTLS negotiation", () => {
  it("ends at the deadline of the check while the server keeps sending EHLO lines", async () => {
    const port = await service((socket) => {
      socket.write("220 mail.example ESMTP\r\n");
      socket.once("data", () => drip(socket, "250-PIPELINING\r\n"));
    });

    await expect(prepareStartTls("127.0.0.1", port, "smtp", 2000, checkLimits(64, 0.5))).rejects.toThrow(
      "The SMTP STARTTLS negotiation did not finish within the 0.5 seconds a check may take."
    );
  });

  it("ends at MONITOR_PROTOCOL_READ_LIMIT_KB", async () => {
    env.monitorProtocolReadLimitKb = 2;
    const port = await service((socket) => {
      socket.write("220 mail.example ESMTP\r\n");
      socket.once("data", () => socket.write("250-PIPELINING\r\n".repeat(200)));
    });

    await expect(prepareStartTls("127.0.0.1", port, "smtp", 2000)).rejects.toThrow("The server sent more than 2 KB during the SMTP STARTTLS negotiation, the most a check reads.");
  });

  it("names the monitor's idle timeout when the server stops answering", async () => {
    const port = await service((socket) => socket.write("220 mail.example ESMTP\r\n"));

    await expect(prepareStartTls("127.0.0.1", port, "smtp", 300, checkLimits(64, 60))).rejects.toThrow("The SMTP STARTTLS negotiation got no answer for 0.3 seconds.");
  });
});

describe("a service check", () => {
  it("ends the banner at the deadline while the service sends a banner without end", async () => {
    const port = await service((socket) => drip(socket, "S"));
    const result = await runServiceCheck(monitor({ type: "ssh", port }), null, undefined, checkLimits(64, 0.5));

    expect(result.status).toBe("DOWN");
    expect(result.message).toBe("The SSH banner check did not finish within the 0.5 seconds a check may take. Check that the server answers promptly, or ask the operator of this crt.watch instance to raise MONITOR_CHECK_DEADLINE_SECONDS.");
  });

  it("ends the banner at the read limit", async () => {
    const port = await service((socket) => socket.write("S".repeat(5000)));
    const result = await runServiceCheck(monitor({ type: "ssh", port }), null, undefined, checkLimits(4, 60));

    expect(result.status).toBe("DOWN");
    expect(result.message).toBe("The server sent more than 4 KB during the SSH banner check, the most a check reads. Check that the monitor uses the right port and protocol, or ask the operator of this crt.watch instance to raise MONITOR_PROTOCOL_READ_LIMIT_KB.");
  });

  it("reads a banner up to the closed connection", async () => {
    const port = await service((socket) => socket.end("SSH-2.0-Closing"));
    const result = await runServiceCheck(monitor({ type: "ssh", port }), null, undefined, checkLimits(64, 60));

    expect(result.status).toBe("OK");
    expect(result.message).toBe("SSH service responded: SSH-2.0-Closing");
  });

  it("counts the banner and the login against one deadline", async () => {
    const port = await service((socket) => setTimeout(() => socket.write("220 FTP ready\r\n"), 300));
    const ftp = monitor({ type: "ftp", port, config: { securityMode: "plain", loginEnabled: true, allowInsecureLogin: true, username: "monitor", password: "for-this-test" } });

    const result = await runServiceCheck(ftp, null, undefined, checkLimits(64, 0.5));

    expect(result.status).toBe("DOWN");
    expect(result.message).toBe("The FTP login did not finish within the 0.5 seconds a check may take. Check that the server answers promptly, or ask the operator of this crt.watch instance to raise MONITOR_CHECK_DEADLINE_SECONDS.");
  });

  it("ends the login at the read limit", async () => {
    const port = await service((socket) => {
      socket.write("220 FTP ready\r\n");
      socket.on("data", () => socket.write("100-Please wait while the server prepares your session\r\n".repeat(100)));
    });
    const ftp = monitor({ type: "ftp", port, config: { securityMode: "plain", loginEnabled: true, allowInsecureLogin: true, username: "monitor", password: "for-this-test" } });

    const result = await runServiceCheck(ftp, null, undefined, checkLimits(1, 60));

    expect(result.status).toBe("DOWN");
    expect(result.message).toMatch(/^The server sent more than 1 KB during the FTP login, the most a check reads\./);
  });
});

describe("the login over TLS", () => {
  // The login only reads and writes lines, so a plain connection stands in for the TLS socket.
  const smtps = monitor({ type: "smtps", config: { loginEnabled: true, username: "monitor", password: "for-this-test" } });

  it("ends at the deadline of the check", async () => {
    const port = await service((socket) => drip(socket, "220-welcome\r\n"));

    await expect(checkTlsLogin(connect(port) as unknown as tls.TLSSocket, smtps, checkLimits(64, 0.4))).rejects.toThrow(
      "The SMTP login over TLS did not finish within the 0.4 seconds a check may take."
    );
  });

  it("ends at the read limit", async () => {
    const port = await service((socket) => socket.write("220-welcome\r\n".repeat(200)));

    await expect(checkTlsLogin(connect(port) as unknown as tls.TLSSocket, smtps, checkLimits(1, 60))).rejects.toThrow(
      "The server sent more than 1 KB during the SMTP login over TLS, the most a check reads."
    );
  });
});

describe("a TLS check", () => {
  it("ends the handshake at the deadline of the check", async () => {
    const port = await service();
    const started = Date.now();

    const result = await runTlsCheck(monitor({ type: "tls", port, timeoutSeconds: 5 }), null, undefined, checkLimits(64, 0.5));

    expect(result.status).toBe("DOWN");
    expect(result.message).toBe("The TLS handshake did not finish within the 0.5 seconds a check may take. Check that the server answers promptly, or ask the operator of this crt.watch instance to raise MONITOR_CHECK_DEADLINE_SECONDS.");
    expect(elapsedSince(started)).toBeLessThan(3000);
  });

  it("names the monitor's idle timeout when the handshake gets no answer", async () => {
    const port = await service();

    const result = await runTlsCheck(monitor({ type: "tls", port, timeoutSeconds: 1 }), null, undefined, checkLimits(64, 60));

    expect(result.message).toBe("The TLS handshake got no answer for 1 second. Check that the service is reachable on this port, or raise the timeout of the monitor.");
  });
});

describe("the TLS version probes", () => {
  const policy: TlsPolicySettings = { profile: "modern", minimumTlsVersion: "TLSv1.2", weakCipherPenalty: 40, requireSan: true, intensiveScan: true };

  it("wait MONITOR_TLS_PROBE_TIMEOUT_SECONDS for an answer", async () => {
    env.monitorTlsProbeTimeoutSeconds = 1;
    const port = await service();
    const started = Date.now();

    await expect(probeSupportedTlsVersions(monitor({ type: "tls", port, timeoutSeconds: 10 }), policy, checkLimits(64, 60))).resolves.toEqual([]);

    expect(elapsedSince(started)).toBeGreaterThanOrEqual(900);
    expect(elapsedSince(started)).toBeLessThan(2500);
  });

  it("end at the deadline of the check", async () => {
    const port = await service();
    const started = Date.now();

    await expect(probeSupportedTlsVersions(monitor({ type: "tls", port, timeoutSeconds: 10 }), policy, checkLimits(64, 0.3))).resolves.toEqual([]);

    expect(elapsedSince(started)).toBeLessThan(1500);
  });
});

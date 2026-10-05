import { removeDatabase } from "./support/isolatedDatabase.js";
import net from "node:net";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

/* Email notifications reach their SMTP server through the same address check
   as webhooks: after DNS, on the address that is connected to, with the same
   settings to open internal networks. */

const resolver = vi.hoisted(() => ({ answers: new Map<string, Array<{ address: string; family: number }>>() }));
vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns")>();
  const lookup = ((hostname: string, options: any, callback: any) => {
    const answer = resolver.answers.get(hostname);
    if (!answer) return actual.lookup(hostname, options, callback);
    if (options?.all) return callback(null, answer);
    return callback(null, answer[0].address, answer[0].family);
  }) as typeof actual.lookup;
  return { ...actual, default: { ...actual, lookup }, lookup };
});

import { connectMailServer, mailTransport, NotificationTargetError, type DeliverySettings } from "../apps/api/src/notifications/delivery.js";
import { testChannel } from "../apps/api/src/notifications/service.js";
import { migrate } from "../apps/api/src/storage/db.js";
import { appSettings } from "../apps/api/src/storage/repositories.js";
import { parseNetworkList } from "../apps/api/src/utils/networks.js";
import type { SmtpSettings } from "../apps/api/src/types.js";
import { organization } from "./support/fixtures.js";

migrate();

const denyInternal: DeliverySettings = { allowPrivateTargets: false, allowedNetworks: [], maxRedirects: 3, timeoutMs: 2000 };
const allowLoopback: DeliverySettings = { ...denyInternal, allowedNetworks: parseNetworkList("127.0.0.1/32", "NOTIFICATION_ALLOWED_NETWORKS") };
const allowAll: DeliverySettings = { ...denyInternal, allowPrivateTargets: true };

type FakeSmtp = { port: number; messages: string[]; connections: () => number; close: () => Promise<void> };
const servers: FakeSmtp[] = [];

// Just enough SMTP for nodemailer to hand over one message without TLS or login.
const fakeSmtpServer = () => new Promise<FakeSmtp>((resolve) => {
  const messages: string[] = [];
  let connections = 0;
  const server = net.createServer((socket) => {
    connections += 1;
    let buffer = "";
    let body: string | null = null;
    socket.write("220 fake.smtp.test ESMTP\r\n");
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      for (let end = buffer.indexOf("\r\n"); end >= 0; end = buffer.indexOf("\r\n")) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (body !== null) {
          if (line === ".") {
            messages.push(body);
            body = null;
            socket.write("250 2.0.0 queued\r\n");
          } else body += `${line}\n`;
          continue;
        }
        const command = line.slice(0, 4).toUpperCase();
        if (command === "EHLO" || command === "HELO") socket.write("250-fake.smtp.test\r\n250 8BITMIME\r\n");
        else if (command === "DATA") {
          body = "";
          socket.write("354 go ahead\r\n");
        } else if (command === "QUIT") {
          socket.write("221 bye\r\n");
          socket.end();
        } else socket.write("250 ok\r\n");
      }
    });
    socket.on("error", () => undefined);
  });
  server.listen(0, "127.0.0.1", () => {
    const fake: FakeSmtp = {
      port: (server.address() as net.AddressInfo).port,
      messages,
      connections: () => connections,
      close: () => new Promise((done) => server.close(() => done()))
    };
    servers.push(fake);
    resolve(fake);
  });
});

const smtp = (host: string, port: number): SmtpSettings => ({ host, port, username: "", password: "", from: "crt.watch@example.com", secure: false, starttls: false });

afterEach(() => resolver.answers.clear());
afterAll(async () => {
  await Promise.all(servers.map((server) => server.close()));
  removeDatabase();
});

describe("SMTP servers", () => {
  it("on an internal address are refused before a connection is opened", async () => {
    const fake = await fakeSmtpServer();

    for (const host of ["127.0.0.1", "10.0.0.5", "169.254.169.254", "[::1]"]) {
      await expect(connectMailServer(host, fake.port, denyInternal)).rejects.toBeInstanceOf(NotificationTargetError);
    }
    await expect(connectMailServer("10.0.0.5", 25, denyInternal)).rejects.toThrow("SMTP server 10.0.0.5 is a private, loopback or link-local address, and crt.watch does not send notifications into internal networks. Use a publicly reachable mail server, or ask the operator of this crt.watch instance to allow the network with NOTIFICATION_ALLOWED_NETWORKS or ALLOW_PRIVATE_NOTIFICATION_TARGETS.");
    expect(fake.connections()).toBe(0);
  });

  it("whose name resolves to an internal address are refused after DNS", async () => {
    const fake = await fakeSmtpServer();
    resolver.answers.set("mail.internal.test", [{ address: "127.0.0.1", family: 4 }]);
    resolver.answers.set("mail.mixed.test", [{ address: "203.0.113.25", family: 4 }, { address: "127.0.0.1", family: 4 }]);

    await expect(connectMailServer("mail.internal.test", fake.port, denyInternal)).rejects.toThrow(/^SMTP server mail\.internal\.test is a private/);
    await expect(connectMailServer("mail.mixed.test", fake.port, denyInternal)).rejects.toThrow(/^SMTP server mail\.mixed\.test is a private/);
    expect(fake.connections()).toBe(0);
  });

  it("are reached on the checked address once the operator allows the network", async () => {
    const fake = await fakeSmtpServer();
    resolver.answers.set("mail.allowed.test", [{ address: "127.0.0.1", family: 4 }]);

    const socket = await connectMailServer("mail.allowed.test", fake.port, allowLoopback);
    expect(socket.remoteAddress).toBe("127.0.0.1");
    socket.destroy();
    const literal = await connectMailServer("127.0.0.1", fake.port, allowAll);
    literal.destroy();
  });

  it("receive the message through nodemailer over the checked connection", async () => {
    const fake = await fakeSmtpServer();

    await mailTransport(smtp("127.0.0.1", fake.port), allowLoopback).sendMail({ from: "crt.watch@example.com", to: "ops@example.com", subject: "Certificate warning", text: "Renew it." });

    expect(fake.messages).toHaveLength(1);
    expect(fake.messages[0]).toContain("Subject: Certificate warning");
  });

  it("refused by the check reach nodemailer's caller as a refused target", async () => {
    const sending = mailTransport(smtp("10.0.0.5", 25), denyInternal).sendMail({ from: "crt.watch@example.com", to: "ops@example.com", subject: "x", text: "x" });

    await expect(sending).rejects.toBeInstanceOf(NotificationTargetError);
  });

  it("must be configured", async () => {
    await expect(connectMailServer("  ", 587, denyInternal)).rejects.toThrow("No SMTP server is configured. Enter the SMTP host in the SMTP settings or in the email channel.");
  });
});

describe("email channel tests", () => {
  it("use the SMTP settings of the channel's own organization and pass the address check", async () => {
    const beta = organization("Beta");
    appSettings.set("smtp", { host: "10.1.1.1", port: 587, username: "", password: "", from: "", secure: false, starttls: true });
    appSettings.set("smtp", { host: "10.9.9.9", port: 587, username: "", password: "", from: "", secure: false, starttls: true }, beta.tenant.id);
    const channel = { id: "channel-1", tenantId: beta.tenant.id, name: "Beta mail", type: "email" as const, enabled: true, config: { to: "ops@beta.example" }, createdAt: "", updatedAt: "" };

    const testing = testChannel(channel);

    await expect(testing).rejects.toBeInstanceOf(NotificationTargetError);
    await expect(testing).rejects.toThrow(/^SMTP server 10\.9\.9\.9 is a private/);
  });
});

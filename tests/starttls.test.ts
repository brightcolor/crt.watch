import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { prepareStartTls } from "../apps/api/src/checks/starttls.js";

const servers: net.Server[] = [];

describe("STARTTLS negotiation", () => {
  afterEach(async () => {
    await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    servers.length = 0;
  });

  it("handles multiline SMTP EHLO responses split across chunks", async () => {
    const port = await startServer((socket) => {
      socket.write("220 mail.example ESMTP ready\r\n");
      socket.on("data", (chunk) => {
        const command = chunk.toString("utf8");
        if (/EHLO/i.test(command)) {
          socket.write("250-mail.example\r\n250-PIPE");
          setTimeout(() => socket.write("LINING\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n"), 5);
        }
        if (/STARTTLS/i.test(command)) socket.write("220 Ready to start TLS\r\n");
      });
    });

    const ready = await prepareStartTls("127.0.0.1", port, "smtp", 1000);
    expect(ready.transcript).toContain("250-STARTTLS");
    ready.socket.destroy();
  });

  it("handles IMAP capability and STARTTLS tagged responses", async () => {
    const port = await startServer((socket) => {
      socket.write("* OK IMAP ready\r\n");
      socket.on("data", (chunk) => {
        const command = chunk.toString("utf8");
        if (/cw001 CAPABILITY/i.test(command)) socket.write("* CAPABILITY IMAP4rev1 UIDPLUS STARTTLS AUTH=PLAIN\r\ncw001 OK CAPABILITY completed\r\n");
        if (/cw002 STARTTLS/i.test(command)) socket.write("cw002 OK Begin TLS negotiation now\r\n");
      });
    });

    const ready = await prepareStartTls("127.0.0.1", port, "imap", 1000);
    expect(ready.transcript.some((line) => line.includes("STARTTLS"))).toBe(true);
    ready.socket.destroy();
  });

  it("handles POP3 CAPA/STLS responses", async () => {
    const port = await startServer((socket) => {
      socket.write("+OK POP3 ready\r\n");
      socket.on("data", (chunk) => {
        const command = chunk.toString("utf8");
        if (/CAPA/i.test(command)) socket.write("+OK Capability list follows\r\nUSER\r\nSTLS\r\n.\r\n");
        if (/STLS/i.test(command)) socket.write("+OK Begin TLS negotiation\r\n");
      });
    });

    const ready = await prepareStartTls("127.0.0.1", port, "pop3", 1000);
    expect(ready.transcript).toContain("STLS");
    ready.socket.destroy();
  });

  it("reads tagged IMAP completions in any case and only as whole words", async () => {
    const port = await startServer((socket) => {
      socket.write("* OK IMAP ready\r\n");
      socket.on("data", (chunk) => {
        const command = chunk.toString("utf8");
        if (/cw001 CAPABILITY/i.test(command)) socket.write("* CAPABILITY IMAP4rev1 STARTTLS\r\ncw001 okay, more to come\r\nCW001 ok CAPABILITY completed\r\n");
        if (/cw002 STARTTLS/i.test(command)) socket.write("cw002 NO STARTTLS is switched off\r\n");
      });
    });

    await expect(prepareStartTls("127.0.0.1", port, "imap", 1000)).rejects.toThrow("IMAP STARTTLS rejected: cw002 NO STARTTLS is switched off");
  });

  it("handles FTP AUTH TLS responses", async () => {
    const port = await startServer((socket) => {
      socket.write("220 FTP ready\r\n");
      socket.on("data", (chunk) => {
        if (/AUTH TLS/i.test(chunk.toString("utf8"))) socket.write("234 Proceed with negotiation.\r\n");
      });
    });

    const ready = await prepareStartTls("127.0.0.1", port, "ftp", 1000);
    expect(ready.transcript).toContain("234 Proceed with negotiation.");
    ready.socket.destroy();
  });
});

const startServer = (handler: (socket: net.Socket) => void) =>
  new Promise<number>((resolve) => {
    const server = net.createServer(handler);
    servers.push(server);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (typeof address === "object" && address) resolve(address.port);
    });
  });

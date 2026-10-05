import net from "node:net";
import { monitorConnectOptions } from "./validation.js";

export interface StartTlsReady {
  socket: net.Socket;
  transcript: string[];
}

export const prepareStartTls = async (host: string, port: number, mode: "smtp" | "imap" | "pop3" | "ftp", timeoutMs: number) => {
  const socket = net.connect({ host, port, ...monitorConnectOptions() });
  socket.setTimeout(timeoutMs);
  const reader = new LineReader(socket);

  try {
    if (mode === "smtp") await prepareSmtp(socket, reader);
    if (mode === "imap") await prepareImap(socket, reader);
    if (mode === "pop3") await preparePop3(socket, reader);
    if (mode === "ftp") await prepareFtp(socket, reader);
    socket.setTimeout(0);
    return { socket, transcript: reader.transcript } satisfies StartTlsReady;
  } catch (error) {
    socket.destroy();
    throw error;
  } finally {
    reader.detach();
  }
};

class LineReader {
  readonly transcript: string[] = [];
  private buffer = "";
  private pendingLines: string[] = [];
  private waiters: Array<() => void> = [];
  private error: Error | null = null;

  constructor(private readonly socket: net.Socket) {
    socket.on("data", this.onData);
    socket.on("error", this.onError);
    socket.on("timeout", this.onTimeout);
    socket.on("end", this.onEnd);
  }

  detach() {
    this.socket.off("data", this.onData);
    this.socket.off("error", this.onError);
    this.socket.off("timeout", this.onTimeout);
    this.socket.off("end", this.onEnd);
  }

  async readUntil(done: (lines: string[]) => boolean): Promise<string[]> {
    const lines: string[] = [];
    while (true) {
      while (this.pendingLines.length) {
        const line = this.pendingLines.shift()!;
        lines.push(line);
        this.transcript.push(line);
        if (done(lines)) return lines;
      }
      if (this.error) throw this.error;
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
  }

  private wake() {
    const waiters = this.waiters.splice(0);
    for (const waiter of waiters) waiter();
  }

  private onData = (chunk: Buffer) => {
    this.buffer += chunk.toString("utf8");
    const parts = this.buffer.split(/\r?\n/);
    this.buffer = parts.pop() ?? "";
    this.pendingLines.push(...parts.filter((line) => line.length > 0));
    this.wake();
  };

  private onError = (error: Error) => {
    this.error = error;
    this.wake();
  };

  private onTimeout = () => {
    this.error = new Error("STARTTLS negotiation timed out.");
    this.wake();
  };

  private onEnd = () => {
    this.error = new Error("Connection closed during STARTTLS negotiation.");
    this.wake();
  };
}

const prepareSmtp = async (socket: net.Socket, reader: LineReader) => {
  await reader.readUntil((lines) => smtpFinal(lines, 220));
  write(socket, "EHLO crt.watch.local");
  const ehloLines = await reader.readUntil((lines) => smtpFinal(lines, 250));
  if (!ehloLines.some((line) => /\bSTARTTLS\b/i.test(line))) throw new Error("SMTP server does not advertise STARTTLS.");
  write(socket, "STARTTLS");
  const startTlsLines = await reader.readUntil((lines) => smtpFinal(lines, 220));
  if (!startTlsLines.some((line) => /^220\b/.test(line))) throw new Error(`SMTP STARTTLS rejected: ${startTlsLines.join(" ")}`);
};

const prepareImap = async (socket: net.Socket, reader: LineReader) => {
  const greeting = await reader.readUntil((lines) => lines.some((line) => /^\* (OK|PREAUTH)/i.test(line)));
  let hasStartTls = greeting.some((line) => /\bSTARTTLS\b/i.test(line));
  write(socket, "cw001 CAPABILITY");
  const capability = await reader.readUntil((lines) => taggedImapDone(lines, "cw001"));
  hasStartTls = hasStartTls || capability.some((line) => /\bSTARTTLS\b/i.test(line));
  if (!hasStartTls) throw new Error("IMAP server does not advertise STARTTLS.");
  write(socket, "cw002 STARTTLS");
  const response = await reader.readUntil((lines) => taggedImapDone(lines, "cw002"));
  if (!response.some((line) => /^cw002 OK\b/i.test(line))) throw new Error(`IMAP STARTTLS rejected: ${response.join(" ")}`);
};

const preparePop3 = async (socket: net.Socket, reader: LineReader) => {
  await reader.readUntil((lines) => lines.some((line) => /^\+OK/i.test(line)));
  write(socket, "CAPA");
  const capability = await reader.readUntil((lines) => lines.some((line) => line === "."));
  if (!capability.some((line) => /^STLS\b/i.test(line))) throw new Error("POP3 server does not advertise STLS.");
  write(socket, "STLS");
  const response = await reader.readUntil((lines) => lines.some((line) => /^(\+OK|-ERR)/i.test(line)));
  if (!response.some((line) => /^\+OK/i.test(line))) throw new Error(`POP3 STLS rejected: ${response.join(" ")}`);
};

const prepareFtp = async (socket: net.Socket, reader: LineReader) => {
  await reader.readUntil((lines) => lines.some((line) => /^220\b/.test(line)));
  write(socket, "AUTH TLS");
  const response = await reader.readUntil((lines) => lines.some((line) => /^(\d{3})\b/.test(line)));
  if (!response.some((line) => /^234\b/.test(line))) throw new Error(`FTP AUTH TLS rejected: ${response.join(" ")}`);
};

const write = (socket: net.Socket, line: string) => socket.write(`${line}\r\n`);

const smtpFinal = (lines: string[], code: number) => {
  const prefix = String(code);
  return lines.some((line) => line.startsWith(`${prefix} `)) || (lines.length === 1 && lines[0].startsWith(prefix) && !lines[0].startsWith(`${prefix}-`));
};

// A tagged IMAP completion: the tag, a space, then OK, NO or BAD as a whole word, in any case.
const imapCompletion = /^(OK|NO|BAD)\b/i;

const taggedImapDone = (lines: string[], tag: string) =>
  lines.some((line) => {
    const prefix = `${tag} `;
    return line.slice(0, prefix.length).toLowerCase() === prefix.toLowerCase() && imapCompletion.test(line.slice(prefix.length));
  });

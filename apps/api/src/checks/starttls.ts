import net from "node:net";
import { checkLimits, ServiceConversation, type CheckLimits } from "./conversation.js";
import { monitorConnectOptions } from "./validation.js";

export type StartTlsMode = "smtp" | "imap" | "pop3" | "ftp";

export interface StartTlsReady {
  socket: net.Socket;
  transcript: string[];
}

/**
 * Connects and negotiates STARTTLS; the socket is then ready for the TLS
 * handshake. The negotiation reads within the limits of the check: the idle
 * timeout, the read limit and the deadline (checks/conversation.ts).
 */
export const prepareStartTls = async (host: string, port: number, mode: StartTlsMode, timeoutMs: number, limits: CheckLimits = checkLimits()) => {
  const socket = net.connect({ host, port, ...monitorConnectOptions() });
  socket.setTimeout(timeoutMs);
  const conversation = new ServiceConversation(socket, `${mode.toUpperCase()} STARTTLS negotiation`, limits, timeoutMs / 1000);

  try {
    if (mode === "smtp") await prepareSmtp(conversation);
    if (mode === "imap") await prepareImap(conversation);
    if (mode === "pop3") await preparePop3(conversation);
    if (mode === "ftp") await prepareFtp(conversation);
    socket.setTimeout(0);
    return { socket, transcript: conversation.transcript } satisfies StartTlsReady;
  } catch (error) {
    socket.destroy();
    throw error;
  } finally {
    conversation.release();
  }
};

const prepareSmtp = async (conversation: ServiceConversation) => {
  await conversation.readUntil((lines) => smtpFinal(lines, 220));
  conversation.write("EHLO crt.watch.local");
  const ehloLines = await conversation.readUntil((lines) => smtpFinal(lines, 250));
  if (!ehloLines.some((line) => /\bSTARTTLS\b/i.test(line))) throw new Error("SMTP server does not advertise STARTTLS.");
  conversation.write("STARTTLS");
  const startTlsLines = await conversation.readUntil((lines) => smtpFinal(lines, 220));
  if (!startTlsLines.some((line) => /^220\b/.test(line))) throw new Error(`SMTP STARTTLS rejected: ${startTlsLines.join(" ")}`);
};

const prepareImap = async (conversation: ServiceConversation) => {
  const greeting = await conversation.readUntil((lines) => lines.some((line) => /^\* (OK|PREAUTH)/i.test(line)));
  let hasStartTls = greeting.some((line) => /\bSTARTTLS\b/i.test(line));
  conversation.write("cw001 CAPABILITY");
  const capability = await conversation.readUntil((lines) => taggedImapDone(lines, "cw001"));
  hasStartTls = hasStartTls || capability.some((line) => /\bSTARTTLS\b/i.test(line));
  if (!hasStartTls) throw new Error("IMAP server does not advertise STARTTLS.");
  conversation.write("cw002 STARTTLS");
  const response = await conversation.readUntil((lines) => taggedImapDone(lines, "cw002"));
  if (!response.some((line) => /^cw002 OK\b/i.test(line))) throw new Error(`IMAP STARTTLS rejected: ${response.join(" ")}`);
};

const preparePop3 = async (conversation: ServiceConversation) => {
  await conversation.readUntil((lines) => lines.some((line) => /^\+OK/i.test(line)));
  conversation.write("CAPA");
  const capability = await conversation.readUntil((lines) => lines.some((line) => line === "."));
  if (!capability.some((line) => /^STLS\b/i.test(line))) throw new Error("POP3 server does not advertise STLS.");
  conversation.write("STLS");
  const response = await conversation.readUntil((lines) => lines.some((line) => /^(\+OK|-ERR)/i.test(line)));
  if (!response.some((line) => /^\+OK/i.test(line))) throw new Error(`POP3 STLS rejected: ${response.join(" ")}`);
};

const prepareFtp = async (conversation: ServiceConversation) => {
  await conversation.readUntil((lines) => lines.some((line) => /^220\b/.test(line)));
  conversation.write("AUTH TLS");
  const response = await conversation.readUntil((lines) => lines.some((line) => /^(\d{3})\b/.test(line)));
  if (!response.some((line) => /^234\b/.test(line))) throw new Error(`FTP AUTH TLS rejected: ${response.join(" ")}`);
};

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

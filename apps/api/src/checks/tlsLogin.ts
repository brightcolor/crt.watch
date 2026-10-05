import type tls from "node:tls";
import type { Monitor } from "../types.js";
import { checkLimits, ServiceConversation, type CheckLimits } from "./conversation.js";

type LoginProtocol = "smtp" | "imap" | "pop3" | "ftp";

const loginProtocols: Record<string, LoginProtocol> = {
  smtp_starttls: "smtp",
  smtps: "smtp",
  imap_starttls: "imap",
  imaps: "imap",
  pop3_starttls: "pop3",
  pop3s: "pop3",
  ftp_starttls: "ftp",
  ftps: "ftp"
};

export const tlsLoginProtocol = (type: string): LoginProtocol | null => loginProtocols[type] ?? null;

export const tlsLoginEnabled = (monitor: Monitor) =>
  Boolean(monitor.config.loginEnabled) && Boolean(tlsLoginProtocol(monitor.type));

export const tlsLoginSuccessMessage = (monitor: Monitor) => {
  const protocol = tlsLoginProtocol(monitor.type)?.toUpperCase() ?? "service";
  return `Certificate, TLS configuration, and ${protocol} login look healthy.`;
};

/** Logs in over the TLS connection of the check; the login reads within the limits of the check (checks/conversation.ts). */
export const checkTlsLogin = async (socket: tls.TLSSocket, monitor: Monitor, limits: CheckLimits = checkLimits()) => {
  const protocol = tlsLoginProtocol(monitor.type);
  if (!protocol) return;
  const conversation = new ServiceConversation(socket, `${protocol.toUpperCase()} login over TLS`, limits, monitor.timeoutSeconds);
  try {
    if (protocol === "smtp") await smtpLogin(conversation, monitor, monitor.type === "smtps");
    if (protocol === "imap") await imapLogin(conversation, monitor, monitor.type === "imaps");
    if (protocol === "pop3") await pop3Login(conversation, monitor, monitor.type === "pop3s");
    if (protocol === "ftp") await ftpLogin(conversation, monitor, monitor.type === "ftps");
  } finally {
    conversation.release();
  }
};

const smtpLogin = async (reader: ServiceConversation, monitor: Monitor, waitGreeting: boolean) => {
  if (waitGreeting) await reader.readUntil((lines) => smtpFinal(lines, 220));
  reader.write("EHLO crt.watch.local");
  await reader.readUntil((lines) => smtpFinal(lines, 250));
  reader.write("AUTH LOGIN");
  const auth = await reader.readUntil((lines) => smtpFinal(lines, 334) || smtpFinal(lines, 503));
  if (auth.some((line) => /^503\b/.test(line))) return;
  reader.write(Buffer.from(credential(monitor, "username")).toString("base64"));
  await reader.readUntil((lines) => smtpFinal(lines, 334));
  reader.write(Buffer.from(credential(monitor, "password")).toString("base64"));
  const done = await reader.readUntil((lines) => smtpFinal(lines, 235) || smtpFinal(lines, 535));
  if (!done.some((line) => /^235\b/.test(line))) throw new Error("SMTP TLS login failed.");
};

const imapLogin = async (reader: ServiceConversation, monitor: Monitor, waitGreeting: boolean) => {
  if (waitGreeting) await reader.readUntil((lines) => lines.some((line) => /^\* (OK|PREAUTH)/i.test(line)));
  reader.write(`cw003 LOGIN "${escapeImap(credential(monitor, "username"))}" "${escapeImap(credential(monitor, "password"))}"`);
  const response = await reader.readUntil((lines) => lines.some((line) => /^cw003 (OK|NO|BAD)\b/i.test(line)));
  if (!response.some((line) => /^cw003 OK\b/i.test(line))) throw new Error("IMAP TLS login failed.");
};

const pop3Login = async (reader: ServiceConversation, monitor: Monitor, waitGreeting: boolean) => {
  if (waitGreeting) await reader.readUntil((lines) => lines.some((line) => /^\+OK/i.test(line)));
  reader.write(`USER ${credential(monitor, "username")}`);
  const user = await reader.readUntil((lines) => lines.some((line) => /^(\+OK|-ERR)/i.test(line)));
  if (!user.some((line) => /^\+OK/i.test(line))) throw new Error("POP3 TLS username was rejected.");
  reader.write(`PASS ${credential(monitor, "password")}`);
  const pass = await reader.readUntil((lines) => lines.some((line) => /^(\+OK|-ERR)/i.test(line)));
  if (!pass.some((line) => /^\+OK/i.test(line))) throw new Error("POP3 TLS login failed.");
};

const ftpLogin = async (reader: ServiceConversation, monitor: Monitor, waitGreeting: boolean) => {
  if (waitGreeting) await reader.readUntil((lines) => lines.some((line) => /^220\b/.test(line)));
  await optionalFtpCommand(reader, "PBSZ 0");
  await optionalFtpCommand(reader, "PROT P");
  reader.write(`USER ${credential(monitor, "username")}`);
  const userResponse = await reader.readUntil((lines) => lines.some((line) => /^(\d{3})\b/.test(line)));
  if (userResponse.some((line) => /^230\b/.test(line))) return;
  if (!userResponse.some((line) => /^331\b/.test(line))) throw new Error("FTP TLS username was rejected.");
  reader.write(`PASS ${credential(monitor, "password")}`);
  const passResponse = await reader.readUntil((lines) => lines.some((line) => /^(\d{3})\b/.test(line)));
  if (!passResponse.some((line) => /^230\b/.test(line))) throw new Error("FTP TLS login failed.");
};

const optionalFtpCommand = async (reader: ServiceConversation, command: string) => {
  reader.write(command);
  await reader.readUntil((lines) => lines.some((line) => /^(\d{3})\b/.test(line)));
};

const smtpFinal = (lines: string[], code: number) => {
  const prefix = String(code);
  return lines.some((line) => line.startsWith(`${prefix} `)) || (lines.length === 1 && lines[0].startsWith(prefix) && !lines[0].startsWith(`${prefix}-`));
};

const credential = (monitor: Monitor, key: "username" | "password") => String(monitor.config[key] ?? "");
const escapeImap = (value: string) => value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

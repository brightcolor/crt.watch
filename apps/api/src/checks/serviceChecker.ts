import dns from "node:dns/promises";
import net from "node:net";
import { Client } from "ssh2";
import type { CheckResult, Monitor, TlsPolicySettings } from "../types.js";
import { id } from "../utils/id.js";
import { nowIso } from "../utils/time.js";
import { checkLimits, ServiceConversation, type CheckLimits } from "./conversation.js";
import { monitorHttpSettings, requestMonitorUrl, type MonitorHttpRequest } from "./httpTarget.js";
import { runSecureServiceCheck } from "./serviceSecurity.js";
import { runTlsCheck } from "./tlsChecker.js";
import { assertAllowedTarget, monitorConnectOptions } from "./validation.js";

export const isServiceMonitor = (type: string) => ["http", "tcp", "dns", "http_login", "ssh", "ftp", "smtp", "imap", "pop3"].includes(type);

// The connections of one check share its limits; see checks/conversation.ts.
export const runServiceCheck = async (monitor: Monitor, previousFingerprint?: string | null, tlsPolicy?: TlsPolicySettings, limits: CheckLimits = checkLimits()): Promise<CheckResult> => {
  const started = Date.now();
  try {
    if (monitor.type === "http" || monitor.type === "http_login") return await checkHttpWithOptionalTls(monitor, started, previousFingerprint, tlsPolicy, limits);
    const secureResult = await runSecureServiceCheck(monitor, previousFingerprint, tlsPolicy, limits);
    if (secureResult) return secureResult;
    if (monitor.type === "tcp") return ok(monitor, started, await checkTcp(monitor));
    if (monitor.type === "dns") return ok(monitor, started, await checkDns(monitor));
    if (monitor.type === "ssh" && loginEnabled(monitor)) return ok(monitor, started, await checkSshLogin(monitor));
    if (["ssh", "ftp", "smtp", "imap", "pop3"].includes(monitor.type)) return ok(monitor, started, await checkBannerProtocol(monitor, limits));
    throw new Error(`Unsupported service monitor type: ${monitor.type}`);
  } catch (error) {
    return result(monitor, "DOWN", "critical", started, error instanceof Error ? error.message : String(error));
  }
};

const checkHttpWithOptionalTls = async (monitor: Monitor, started: number, previousFingerprint: string | null | undefined, tlsPolicy: TlsPolicySettings | undefined, limits: CheckLimits) => {
  const tlsResult = httpUsesTls(monitor) ? await runTlsCheck({ ...monitor, type: "https" }, previousFingerprint, tlsPolicy, limits) : null;
  if (tlsResult?.status === "DOWN" && !tlsResult.fingerprintSha256) return tlsResult;
  try {
    const message = await checkHttp(monitor);
    return tlsResult ? mergeServiceSuccess(tlsResult, message) : ok(monitor, started, message);
  } catch (error) {
    if (!tlsResult) throw error;
    const message = error instanceof Error ? error.message : String(error);
    return { ...tlsResult, status: "DOWN" as const, severity: "critical" as const, message, problems: [message, ...tlsResult.problems], rawError: message };
  }
};

// Every connection of a check passes the monitor target policy; see validation.ts.
const connectTarget = (monitor: Monitor) => net.connect({ host: monitor.host, port: monitor.port, ...monitorConnectOptions() });

const checkTcp = async (monitor: Monitor) => {
  await assertAllowedTarget(monitor.host);
  await new Promise<void>((resolve, reject) => {
    const socket = connectTarget(monitor);
    socket.setTimeout(monitor.timeoutSeconds * 1000);
    socket.once("connect", () => {
      socket.destroy();
      resolve();
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("TCP connection timed out."));
    });
    socket.once("error", reject);
  });
  return `TCP port ${monitor.port} is reachable.`;
};

const checkDns = async (monitor: Monitor) => {
  const recordType = String(monitor.config.recordType ?? "A").toUpperCase();
  const expected = String(monitor.config.expectedValue ?? "");
  const records = await dns.resolve(monitor.host, recordType as any);
  const flat = records.flat().map(String);
  if (expected && !flat.some((record) => record.includes(expected))) throw new Error(`DNS ${recordType} result did not contain expected value.`);
  return `DNS ${recordType} resolved ${flat.length} record(s).`;
};

const checkBannerProtocol = async (monitor: Monitor, limits: CheckLimits) => {
  await assertAllowedTarget(monitor.host);
  const banner = await readBanner(monitor, limits);
  const expected = expectedBanner(monitor.type);
  if (!expected.test(banner)) throw new Error(`${monitor.type.toUpperCase()} banner was unexpected: ${banner || "empty response"}.`);
  if (loginEnabled(monitor)) {
    await ensurePlainLoginAllowed(monitor);
    await checkTextProtocolLogin(monitor, limits);
    return `${monitor.type.toUpperCase()} service responded and login succeeded.`;
  }
  return `${monitor.type.toUpperCase()} service responded: ${banner.slice(0, 120)}`;
};

const checkSshLogin = async (monitor: Monitor) => {
  await assertAllowedTarget(monitor.host);
  await new Promise<void>((resolve, reject) => {
    const client = new Client();
    const timer = setTimeout(() => {
      client.end();
      reject(new Error("SSH login timed out."));
    }, monitor.timeoutSeconds * 1000);
    client.once("ready", () => {
      clearTimeout(timer);
      client.end();
      resolve();
    });
    client.once("error", (error) => {
      clearTimeout(timer);
      reject(new Error(`SSH login failed: ${error.message}`));
    });
    // ssh2 talks over the guarded connection instead of opening its own.
    client.connect({
      sock: connectTarget(monitor),
      username: credential(monitor, "username"),
      password: credential(monitor, "password"),
      readyTimeout: monitor.timeoutSeconds * 1000
    });
  });
  return "SSH login succeeded.";
};

// The banner is what the service sends until it is complete or the service closes the connection.
const readBanner = async (monitor: Monitor, limits: CheckLimits) => {
  const socket = connectTarget(monitor);
  socket.setTimeout(monitor.timeoutSeconds * 1000);
  const conversation = new ServiceConversation(socket, `${monitor.type.toUpperCase()} banner check`, limits, monitor.timeoutSeconds);
  socket.once("connect", () => {
    if (monitor.type === "smtp") conversation.write("EHLO crt.watch.local");
    if (monitor.type === "imap") conversation.write("a001 CAPABILITY");
    if (monitor.type === "pop3") conversation.write("CAPA");
  });
  try {
    return (await conversation.readText((text) => bannerComplete(monitor.type, text))).trim();
  } finally {
    socket.destroy();
    conversation.release();
  }
};

const expectedBanner = (type: string) => ({
  ssh: /^SSH-/i,
  ftp: /^220/i,
  smtp: /^220|250[\s-]/im,
  imap: /^\* OK|CAPABILITY/im,
  pop3: /^\+OK|^CAPA/im
}[type] ?? /./);

const bannerComplete = (type: string, buffer: string) => {
  if (type === "ssh" || type === "ftp") return /\r?\n/.test(buffer);
  if (type === "smtp") return /^250 /m.test(buffer) || /^220/m.test(buffer);
  if (type === "imap") return /^a001 (OK|NO|BAD)/im.test(buffer) || /^\* OK/im.test(buffer);
  if (type === "pop3") return /\r?\n\.\r?\n/.test(buffer) || /^\+OK/im.test(buffer);
  return /\r?\n/.test(buffer);
};

const checkHttp = async (monitor: Monitor) => {
  await assertAllowedTarget(monitor.host);
  const url = buildUrl(monitor);
  const expectedText = String(monitor.config.expectedText ?? "");
  const settings = monitorHttpSettings(monitor);
  const response = await requestMonitorUrl({ url, ...httpRequestOf(monitor), readBody: Boolean(expectedText) }, settings);
  const expectedStatus = Number(monitor.config.expectedStatus ?? 200);
  if (response.status !== expectedStatus) throw new Error(`HTTP status ${response.status}, expected ${expectedStatus}.`);
  if (expectedText && !response.body.includes(expectedText)) {
    throw new Error(response.bodyTruncated
      ? `HTTP response did not contain the expected text within its first ${settings.bodyLimitBytes / 1024} KB. Check the expected text, or ask the operator to raise MONITOR_HTTP_BODY_LIMIT_KB.`
      : "HTTP response did not contain expected text.");
  }
  const expectedHeader = parseExpectedHeader(String(monitor.config.expectedHeader ?? ""));
  if (expectedHeader && !response.header(expectedHeader.name)?.includes(expectedHeader.value)) throw new Error(`HTTP header ${expectedHeader.name} did not contain expected value.`);
  return `${url} returned HTTP ${response.status}.`;
};

/* The request of an HTTP monitor. Basic authentication follows redirects and
   drops the credentials when one leads to another origin; a form login posts
   once and reports the redirect it gets as the answer. */
const httpRequestOf = (monitor: Monitor): Omit<MonitorHttpRequest, "url" | "readBody"> => {
  if (monitor.type !== "http_login") return { method: "GET", headers: {}, followRedirects: Boolean(monitor.config.followRedirects) };
  const username = String(monitor.config.username ?? "");
  const password = String(monitor.config.password ?? "");
  if (monitor.config.authType === "basic") {
    return { method: "GET", headers: { authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}` }, followRedirects: true };
  }
  const body = new URLSearchParams({
    [String(monitor.config.usernameField ?? "username")]: username,
    [String(monitor.config.passwordField ?? "password")]: password
  }).toString();
  return { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body, followRedirects: false };
};

const parseExpectedHeader = (value: string) => {
  const [name, ...rest] = value.split(":");
  const headerValue = rest.join(":").trim();
  return name?.trim() && headerValue ? { name: name.trim(), value: headerValue } : null;
};

const checkTextProtocolLogin = async (monitor: Monitor, limits: CheckLimits) => {
  const socket = connectTarget(monitor);
  socket.setTimeout(monitor.timeoutSeconds * 1000);
  const reader = new ServiceConversation(socket, `${monitor.type.toUpperCase()} login`, limits, monitor.timeoutSeconds);
  try {
    if (monitor.type === "ftp") await ftpLogin(reader, monitor);
    else if (monitor.type === "smtp") await smtpLogin(reader, monitor);
    else if (monitor.type === "imap") await imapLogin(reader, monitor);
    else if (monitor.type === "pop3") await pop3Login(reader, monitor);
  } finally {
    socket.destroy();
    reader.release();
  }
};

const ftpLogin = async (reader: ServiceConversation, monitor: Monitor) => {
  await reader.readLine((line) => /^220\b/.test(line));
  reader.write(`USER ${credential(monitor, "username")}`);
  const userResponse = await reader.readLine((line) => /^(230|331)\b/.test(line));
  if (/^230\b/.test(userResponse)) return;
  reader.write(`PASS ${credential(monitor, "password")}`);
  const passResponse = await reader.readLine((line) => /^(\d{3})\b/.test(line));
  if (!/^230\b/.test(passResponse)) throw new Error("FTP login failed.");
};

const smtpLogin = async (reader: ServiceConversation, monitor: Monitor) => {
  await reader.readLine((line) => /^220\b/.test(line));
  reader.write("EHLO crt.watch.local");
  await reader.readLine((line) => /^250 /.test(line));
  reader.write("AUTH LOGIN");
  const authResponse = await reader.readLine((line) => /^(\d{3})\b/.test(line));
  if (!/^334\b/.test(authResponse)) throw new Error("SMTP AUTH LOGIN was rejected.");
  reader.write(Buffer.from(credential(monitor, "username")).toString("base64"));
  const userResponse = await reader.readLine((line) => /^(\d{3})\b/.test(line));
  if (!/^334\b/.test(userResponse)) throw new Error("SMTP username was rejected.");
  reader.write(Buffer.from(credential(monitor, "password")).toString("base64"));
  const passResponse = await reader.readLine((line) => /^(\d{3})\b/.test(line));
  if (!/^235\b/.test(passResponse)) throw new Error("SMTP login failed.");
};

const imapLogin = async (reader: ServiceConversation, monitor: Monitor) => {
  await reader.readLine((line) => /^\* (OK|PREAUTH)/i.test(line));
  reader.write(`a001 LOGIN "${escapeImap(credential(monitor, "username"))}" "${escapeImap(credential(monitor, "password"))}"`);
  const response = await reader.readLine((line) => /^a001 (OK|NO|BAD)\b/i.test(line));
  if (!/^a001 OK\b/i.test(response)) throw new Error("IMAP login failed.");
};

const pop3Login = async (reader: ServiceConversation, monitor: Monitor) => {
  await reader.readLine((line) => /^\+OK/i.test(line));
  reader.write(`USER ${credential(monitor, "username")}`);
  const userResponse = await reader.readLine((line) => /^(\+OK|-ERR)/i.test(line));
  if (!/^\+OK/i.test(userResponse)) throw new Error("POP3 username was rejected.");
  reader.write(`PASS ${credential(monitor, "password")}`);
  const passResponse = await reader.readLine((line) => /^(\+OK|-ERR)/i.test(line));
  if (!/^\+OK/i.test(passResponse)) throw new Error("POP3 login failed.");
};

const loginEnabled = (monitor: Monitor) => Boolean(monitor.config.loginEnabled);
const credential = (monitor: Monitor, key: "username" | "password") => String(monitor.config[key] ?? "");
const ensurePlainLoginAllowed = async (monitor: Monitor) => {
  if (monitor.type === "ssh" || monitor.config.allowInsecureLogin) return;
  throw new Error(`${monitor.type.toUpperCase()} login over plaintext is disabled. Enable it explicitly or use a TLS/STARTTLS monitor.`);
};
const escapeImap = (value: string) => value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

const buildUrl = (monitor: Monitor) => {
  const scheme = String(monitor.config.scheme ?? (monitor.port === 443 ? "https" : "http"));
  const path = String(monitor.config.path ?? "/");
  return `${scheme}://${monitor.host}:${monitor.port}${path.startsWith("/") ? path : `/${path}`}`;
};

const ok = (monitor: Monitor, started: number, message: string) => result(monitor, "OK", "info", started, message);

const httpUsesTls = (monitor: Monitor) => String(monitor.config.scheme ?? (monitor.port === 443 ? "https" : "http")).toLowerCase() === "https";

const mergeServiceSuccess = (tlsResult: CheckResult, message: string): CheckResult =>
  tlsResult.problems.length ? { ...tlsResult, problems: [...tlsResult.problems, message] } : { ...tlsResult, message: `${message} Certificate and TLS configuration look healthy.` };

const result = (monitor: Monitor, status: CheckResult["status"], severity: CheckResult["severity"], started: number, message: string): CheckResult => ({
  id: id(),
  monitorId: monitor.id,
  status,
  severity,
  message,
  checkedAt: nowIso(),
  durationMs: Date.now() - started,
  daysRemaining: null,
  validFrom: null,
  validUntil: null,
  commonName: null,
  subjectAltNames: [],
  issuer: null,
  serialNumber: null,
  fingerprintSha256: null,
  tlsVersion: null,
  cipherSuite: null,
  tlsGrade: null,
  tlsScore: null,
  tlsSupportedVersions: [],
  flapping: false,
  chain: [],
  problems: status === "OK" ? [] : [message],
  rawError: status === "OK" ? null : message
});

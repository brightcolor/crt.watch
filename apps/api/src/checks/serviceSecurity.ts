import type { CheckResult, Monitor, TlsPolicySettings } from "../types.js";
import { checkLimits, type CheckLimits } from "./conversation.js";
import { runTlsCheck } from "./tlsChecker.js";

export type ServiceSecurityMode = "auto" | "plain" | "starttls" | "tls";

interface TransportAttempt {
  type: Monitor["type"];
  mode: Exclude<ServiceSecurityMode, "auto" | "plain">;
  label: string;
}

const startTlsTypes: Partial<Record<string, Monitor["type"]>> = {
  smtp: "smtp_starttls",
  imap: "imap_starttls",
  pop3: "pop3_starttls",
  ftp: "ftp_starttls"
};

const tlsTypes: Partial<Record<string, Monitor["type"]>> = {
  tcp: "tls",
  smtp: "smtps",
  imap: "imaps",
  pop3: "pop3s",
  ftp: "ftps"
};

const implicitTlsPorts: Record<string, number> = {
  smtp: 465,
  imap: 993,
  pop3: 995,
  ftp: 990
};

export const supportsTransportSecurity = (type: string) => Boolean(startTlsTypes[type] || tlsTypes[type]);

export const serviceSecurityMode = (monitor: Pick<Monitor, "type" | "config">): ServiceSecurityMode => {
  const configured = String(monitor.config?.securityMode ?? "").toLowerCase();
  if (configured === "plain" || configured === "starttls" || configured === "tls" || configured === "auto") return configured;
  return ["ftp", "smtp", "imap", "pop3"].includes(monitor.type) ? "auto" : "plain";
};

export const serviceTransportAttempts = (monitor: Pick<Monitor, "type" | "port" | "config">): TransportAttempt[] => {
  const mode = serviceSecurityMode(monitor as Pick<Monitor, "type" | "config">);
  if (mode === "plain" || !supportsTransportSecurity(monitor.type)) return [];
  if (mode === "starttls") return startTlsTypes[monitor.type] ? [attempt(monitor.type, "starttls")] : [];
  if (mode === "tls") return tlsTypes[monitor.type] ? [attempt(monitor.type, "tls")] : [];
  const available = [startTlsTypes[monitor.type] ? attempt(monitor.type, "starttls") : null, tlsTypes[monitor.type] ? attempt(monitor.type, "tls") : null].filter(Boolean) as TransportAttempt[];
  return monitor.port === implicitTlsPorts[monitor.type] ? available.reverse() : available;
};

// The transport attempts belong to one check and share its limits.
export const runSecureServiceCheck = async (
  monitor: Monitor,
  previousFingerprint?: string | null,
  tlsPolicy?: TlsPolicySettings,
  limits: CheckLimits = checkLimits()
): Promise<CheckResult | null> => {
  const attempts = serviceTransportAttempts(monitor);
  let lastResult: CheckResult | null = null;
  for (const attempt of attempts) {
    const result = annotateTransportResult(await runTlsCheck({ ...monitor, type: attempt.type }, previousFingerprint, tlsPolicy, limits), attempt, serviceSecurityMode(monitor) === "auto");
    if (isUsableSecureResult(result)) return result;
    lastResult = result;
  }
  return serviceSecurityMode(monitor) === "auto" ? null : lastResult;
};

const attempt = (protocol: string, mode: TransportAttempt["mode"]): TransportAttempt => ({
  type: (mode === "starttls" ? startTlsTypes[protocol] : tlsTypes[protocol])!,
  mode,
  label: `${protocol.toUpperCase()} ${mode === "starttls" ? "STARTTLS" : "SSL/TLS"}`
});

const isUsableSecureResult = (result: CheckResult) =>
  result.status !== "DOWN" || Boolean(result.fingerprintSha256 || result.tlsVersion);

const annotateTransportResult = (result: CheckResult, attempt: TransportAttempt, auto: boolean): CheckResult => {
  const prefix = auto ? `Auto selected ${attempt.label}` : attempt.label;
  if (!result.problems.length) return { ...result, message: `${prefix}. ${result.message}` };
  return {
    ...result,
    message: `${prefix}: ${result.message}`,
    problems: result.problems.map((problem, index) => index === 0 ? `${prefix}: ${problem}` : problem)
  };
};

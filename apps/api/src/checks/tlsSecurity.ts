import type net from "node:net";
import tls from "node:tls";
import { env } from "../config/env.js";
import type { Monitor, TlsPolicySettings } from "../types.js";
import { checkLimits, onDeadline, type CheckLimits } from "./conversation.js";
import { prepareStartTls, type StartTlsMode } from "./starttls.js";
import { monitorConnectOptions } from "./validation.js";

type TlsVersion = "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";
type FindingSeverity = "warning" | "critical";

export interface TlsSecurityContext {
  tlsVersion?: string | null;
  cipherSuite?: string | null;
  keyType?: string | null;
  keySize?: number | null;
  namedCurve?: string | null;
  chainLength: number;
  supportedVersions: string[];
}

export interface TlsSecurityFinding {
  severity: FindingSeverity;
  message: string;
}

const versions: TlsVersion[] = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];

/* Each probe waits MONITOR_TLS_PROBE_TIMEOUT_SECONDS for an answer, or the
   monitor's timeout when that is shorter, and ends with the deadline of the
   check like its other connections. A probe that gets no handshake counts
   the version as unsupported. */
export const probeSupportedTlsVersions = async (monitor: Monitor, policy: TlsPolicySettings, limits: CheckLimits = checkLimits()) => {
  if (policy.intensiveScan === false || limits.signal.aborted) return [];
  const timeoutMs = Math.min(monitor.timeoutSeconds, env.monitorTlsProbeTimeoutSeconds) * 1000;
  const results = await Promise.all(versions.map(async (version) => ({ version, supported: await probeVersion(monitor, version, timeoutMs, limits) })));
  return results.filter((result) => result.supported).map((result) => result.version);
};

export const assessTlsSecurity = (context: TlsSecurityContext, policy: TlsPolicySettings): TlsSecurityFinding[] => [
  ...protocolFindings(context, policy),
  ...cipherFindings(context.cipherSuite),
  ...keyFindings(context),
  ...chainFindings(context.chainLength)
];

const protocolFindings = (context: TlsSecurityContext, policy: TlsPolicySettings) => {
  const findings: TlsSecurityFinding[] = [];
  const deprecated = context.supportedVersions.filter((version) => version === "TLSv1" || version === "TLSv1.1");
  if (deprecated.length) findings.push({ severity: "warning", message: `TLS assessment: deprecated protocols are still accepted (${deprecated.join(", ")}).` });
  if (context.supportedVersions.length && !context.supportedVersions.some((version) => version === "TLSv1.2" || version === "TLSv1.3")) {
    findings.push({ severity: "critical", message: "TLS assessment: no modern TLS protocol could be negotiated." });
  }
  if (policy.profile === "strict" && context.supportedVersions.length && !context.supportedVersions.includes("TLSv1.3")) {
    findings.push({ severity: "warning", message: "TLS assessment: strict policy expects TLSv1.3 support." });
  }
  if (context.tlsVersion && versionRank(context.tlsVersion) < versionRank(policy.minimumTlsVersion)) {
    findings.push({ severity: "critical", message: `TLS assessment: negotiated ${context.tlsVersion}, below policy minimum ${policy.minimumTlsVersion}.` });
  }
  return findings;
};

const cipherFindings = (cipherSuite?: string | null) => {
  const cipher = cipherSuite ?? "";
  const findings: TlsSecurityFinding[] = [];
  if (!cipher) return findings;
  if (/NULL|EXPORT|RC4|3DES|DES|MD5/i.test(cipher)) findings.push({ severity: "critical", message: `TLS assessment: weak cipher suite negotiated (${cipher}).` });
  if (/CBC/i.test(cipher)) findings.push({ severity: "warning", message: `TLS assessment: CBC-mode cipher suite negotiated (${cipher}).` });
  if (/^TLS_RSA_|_RSA_WITH_/i.test(cipher) && !/ECDHE|DHE/i.test(cipher)) findings.push({ severity: "warning", message: "TLS assessment: negotiated cipher does not provide forward secrecy." });
  if (/-SHA$/i.test(cipher) || /_SHA$/i.test(cipher)) findings.push({ severity: "warning", message: `TLS assessment: SHA-1 based cipher suite negotiated (${cipher}).` });
  return findings;
};

const keyFindings = ({ keyType, keySize, namedCurve }: TlsSecurityContext) => {
  const findings: TlsSecurityFinding[] = [];
  if (keyType === "rsa" && keySize && keySize < 2048) findings.push({ severity: "critical", message: `TLS assessment: RSA certificate key is only ${keySize} bits.` });
  if (keyType === "ec" && namedCurve && /192|224/i.test(namedCurve)) findings.push({ severity: "warning", message: `TLS assessment: small elliptic curve is used (${namedCurve}).` });
  return findings;
};

const chainFindings = (chainLength: number) =>
  chainLength <= 1 ? [{ severity: "warning" as const, message: "TLS assessment: peer did not send an intermediate certificate chain." }] : [];

const probeVersion = async (monitor: Monitor, version: TlsVersion, timeoutMs: number, limits: CheckLimits) => {
  let rawSocket: net.Socket | undefined;
  try {
    if (monitor.type.endsWith("_starttls")) {
      rawSocket = (await prepareStartTls(monitor.host, monitor.port, monitor.type.split("_")[0] as StartTlsMode, timeoutMs, limits)).socket;
    }
  } catch {
    return false;
  }
  return new Promise<boolean>((resolve) => {
    let stopDeadline = () => {};
    let socket: tls.TLSSocket;
    try {
      socket = tls.connect({
        host: monitor.host,
        port: monitor.port,
        servername: monitor.sniEnabled ? monitor.sniHost || monitor.host : undefined,
        rejectUnauthorized: false,
        timeout: timeoutMs,
        minVersion: version as tls.SecureVersion,
        maxVersion: version as tls.SecureVersion,
        ...(rawSocket ? { socket: rawSocket } : monitorConnectOptions())
      });
    } catch {
      rawSocket?.destroy();
      return resolve(false);
    }
    const done = (supported: boolean) => {
      stopDeadline();
      socket.destroy();
      rawSocket?.destroy();
      resolve(supported);
    };
    stopDeadline = onDeadline(limits, () => done(false));
    socket.once("secureConnect", () => done(true));
    socket.on("error", () => done(false));
    socket.once("timeout", () => done(false));
  });
};

const versionRank = (version: string) => ({ TLSv1: 1, "TLSv1.1": 2, "TLSv1.2": 3, "TLSv1.3": 4 }[version] ?? 0);

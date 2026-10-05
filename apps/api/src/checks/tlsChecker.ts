import tls from "node:tls";
import { X509Certificate } from "node:crypto";
import type { PeerCertificate } from "node:tls";
import type { CheckResult, Monitor, TlsPolicySettings } from "../types.js";
import { id } from "../utils/id.js";
import { nowIso } from "../utils/time.js";
import { classifyResult } from "./status.js";
import { assertAllowedTarget, monitorConnectOptions } from "./validation.js";
import { checkLimits, deadlinePassed, noAnswer, onDeadline, type CheckLimits } from "./conversation.js";
import { prepareStartTls, type StartTlsMode } from "./starttls.js";
import { gradeTls } from "./tlsGrade.js";
import { checkTlsLogin, tlsLoginEnabled, tlsLoginProtocol, tlsLoginSuccessMessage } from "./tlsLogin.js";
import { assessTlsSecurity, probeSupportedTlsVersions } from "./tlsSecurity.js";

// The connections of one check share its limits; see checks/conversation.ts.
export const runTlsCheck = async (monitor: Monitor, previousFingerprint?: string | null, tlsPolicy?: TlsPolicySettings, limits: CheckLimits = checkLimits()): Promise<CheckResult> => {
  const started = Date.now();
  let connection: { socket: tls.TLSSocket; authorized: boolean } | undefined;
  try {
    await assertAllowedTarget(monitor.host);
    connection = await openTlsConnection(monitor, limits);
    const cert = connection.socket.getPeerCertificate(true) as PeerCertificate;
    const x509 = cert.raw ? new X509Certificate(cert.raw) : null;
    const subjectAltNames = parseSan(x509?.subjectAltName ?? "");
    const parsedCommonName = parseDn(String(x509?.subject ?? cert.subject?.CN ?? "")).CN;
    const commonName = parsedCommonName || String(cert.subject?.CN ?? "") || null;
    const validFrom = x509 ? new Date(x509.validFrom) : cert.valid_from ? new Date(cert.valid_from) : undefined;
    const validUntil = x509 ? new Date(x509.validTo) : cert.valid_to ? new Date(cert.valid_to) : undefined;
    const fingerprint = x509?.fingerprint256.replaceAll(":", "").toLowerCase() ?? cert.fingerprint256?.replaceAll(":", "").toLowerCase();
    const selfSigned = Boolean(x509 && x509.subject === x509.issuer);
    const hostnameMatch = matchHostname(monitor.sniHost || monitor.host, commonName, subjectAltNames);
    const loginProblem = tlsLoginAllowed(monitor, { authorized: connection.authorized, hostnameMatch, selfSigned })
      ? await getTlsLoginProblem(connection.socket, monitor, limits)
      : tlsLoginEnabled(monitor) ? skippedTlsLoginProblem(monitor) : null;
    const chain = buildChain(cert);
    const tlsVersion = connection.socket.getProtocol();
    const cipherSuite = connection.socket.getCipher()?.name;
    const supportedVersions = await probeSupportedTlsVersions(monitor, tlsPolicy ?? defaultTlsPolicy, limits);
    const assessment = assessTlsSecurity({
      tlsVersion,
      cipherSuite,
      chainLength: chain.length,
      supportedVersions,
      ...certificateKeyInfo(x509)
    }, tlsPolicy ?? defaultTlsPolicy);
    const classified = classifyResult(monitor, {
      validUntil,
      validFrom,
      hostnameMatch,
      trusted: connection.authorized,
      selfSigned,
      handshakeOk: true,
      reachable: true,
      tlsVersion: tlsVersion ?? undefined,
      previousFingerprint,
      fingerprint,
      chainProblems: chain.length <= 1 ? ["Certificate chain contains no intermediate certificates."] : []
    });
    const assessmentProblems = assessment.map((finding) => finding.message);
    const problems = [...(loginProblem ? [loginProblem] : []), ...classified.problems, ...assessmentProblems];
    const assessmentCritical = assessment.some((finding) => finding.severity === "critical");
    const assessmentWarning = assessment.length > 0;
    const status = loginProblem || assessmentCritical ? "CRITICAL" : classified.status === "OK" && assessmentWarning ? "WARNING" : classified.status;
    const severity = status === "CRITICAL" ? "critical" : status === "WARNING" && classified.severity === "info" ? "warning" : classified.severity;

    const result = withTlsGrade(makeResult(monitor, status, severity, started, problems, {
      message: !problems.length && tlsLoginEnabled(monitor) ? tlsLoginSuccessMessage(monitor) : undefined,
      daysRemaining: classified.daysRemaining,
      validFrom: validFrom?.toISOString(),
      validUntil: validUntil?.toISOString(),
      commonName,
      subjectAltNames,
      issuer: parseDn(x509?.issuer ?? "").O ?? x509?.issuer ?? null,
      serialNumber: x509?.serialNumber ?? cert.serialNumber ?? null,
      fingerprintSha256: fingerprint,
      tlsVersion,
      cipherSuite,
      tlsSupportedVersions: supportedVersions,
      chain
    }), tlsPolicy);
    return result;
  } catch (error) {
    return withTlsGrade(makeResult(monitor, "DOWN", "critical", started, [error instanceof Error ? error.message : "Check failed."], {
      rawError: error instanceof Error ? error.message : String(error)
    }), tlsPolicy);
  } finally {
    connection?.socket.destroy();
  }
};

const openTlsConnection = async (monitor: Monitor, limits: CheckLimits) => {
  const timeoutMs = monitor.timeoutSeconds * 1000;
  const servername = monitor.sniEnabled ? monitor.sniHost || monitor.host : undefined;
  // The handshake must succeed for expired, self-signed or mismatched certificates,
  // because reporting them is the point of the check. socket.authorized carries the
  // verdict; credentials are only sent when tlsLoginAllowed accepts it.
  const options = { host: monitor.host, port: monitor.port, servername, rejectUnauthorized: false, timeout: timeoutMs };
  const rawSocket = monitor.type.endsWith("_starttls")
    ? (await prepareStartTls(monitor.host, monitor.port, monitor.type.split("_")[0] as StartTlsMode, timeoutMs, limits)).socket
    : undefined;
  return new Promise<{ socket: tls.TLSSocket; authorized: boolean }>((resolve, reject) => {
    let socket: tls.TLSSocket;
    try {
      socket = rawSocket ? tls.connect({ ...options, socket: rawSocket }) : tls.connect({ ...options, ...monitorConnectOptions() });
    } catch (error) {
      rawSocket?.destroy();
      return reject(error);
    }
    let settled = false;
    let stopDeadline = () => {};
    const settle = () => {
      settled = true;
      stopDeadline();
      socket.off("timeout", onTimeout);
    };
    const fail = (error: Error) => {
      if (settled) return;
      settle();
      socket.destroy();
      reject(error);
    };
    const onTimeout = () => fail(noAnswer("TLS handshake", monitor.timeoutSeconds));
    stopDeadline = onDeadline(limits, () => fail(deadlinePassed("TLS handshake", limits)));
    socket.once("secureConnect", () => {
      if (settled) return;
      settle();
      resolve({ socket, authorized: socket.authorized });
    });
    // Stays as long as the socket: an error after the handshake ends the login or the check, which own the socket then.
    socket.on("error", fail);
    socket.on("timeout", onTimeout);
  });
};

const makeResult = (
  monitor: Monitor,
  status: CheckResult["status"],
  severity: CheckResult["severity"],
  started: number,
  problems: string[],
  data: Partial<CheckResult> = {}
): CheckResult => ({
  id: id(),
  monitorId: monitor.id,
  status,
  severity,
  message: data.message ?? (problems.length ? problems[0] : "Certificate and TLS configuration look healthy."),
  checkedAt: nowIso(),
  durationMs: Date.now() - started,
  daysRemaining: data.daysRemaining ?? null,
  validFrom: data.validFrom ?? null,
  validUntil: data.validUntil ?? null,
  commonName: data.commonName ?? null,
  subjectAltNames: data.subjectAltNames ?? [],
  issuer: data.issuer ?? null,
  serialNumber: data.serialNumber ?? null,
  fingerprintSha256: data.fingerprintSha256 ?? null,
  tlsVersion: data.tlsVersion ?? null,
  cipherSuite: data.cipherSuite ?? null,
  tlsSupportedVersions: data.tlsSupportedVersions ?? [],
  chain: data.chain ?? [],
  problems,
  rawError: data.rawError ?? null
});

const withTlsGrade = (result: CheckResult, tlsPolicy?: TlsPolicySettings): CheckResult => ({ ...result, ...gradeTls(result, tlsPolicy) });
const defaultTlsPolicy: TlsPolicySettings = { profile: "modern", minimumTlsVersion: "TLSv1.2", weakCipherPenalty: 40, requireSan: true, intensiveScan: true };

const parseDn = (dn: string) =>
  Object.fromEntries(dn.split(/\n|, /).map((part) => {
    const [key, ...value] = part.split("=");
    return [key?.trim(), value.join("=").trim()];
  }));

const parseSan = (value: string) =>
  value.split(/,\s*/).map((entry) => entry.replace(/^DNS:/, "").trim()).filter(Boolean);

const matchHostname = (host: string, commonName: string | null, sans: string[]) => {
  const names = sans.length ? sans : commonName ? [commonName] : [];
  return names.some((name) => name === host || (name.startsWith("*.") && host.endsWith(name.slice(1))));
};

const buildChain = (cert: PeerCertificate) => {
  const items = [];
  let current: PeerCertificate | undefined = cert;
  const seen = new Set<string>();
  while (current && current.raw && !seen.has(current.raw.toString("base64"))) {
    seen.add(current.raw.toString("base64"));
    const x509 = new X509Certificate(current.raw);
    items.push({
      subject: x509.subject,
      issuer: x509.issuer,
      validFrom: new Date(x509.validFrom).toISOString(),
      validUntil: new Date(x509.validTo).toISOString(),
      fingerprintSha256: x509.fingerprint256.replaceAll(":", "").toLowerCase(),
      serialNumber: x509.serialNumber
    });
    const withIssuer = current as PeerCertificate & { issuerCertificate?: PeerCertificate };
    const issuerCertificate: PeerCertificate | undefined = withIssuer.issuerCertificate;
    current = issuerCertificate && issuerCertificate !== current ? issuerCertificate : undefined;
  }
  return items;
};

const getTlsLoginProblem = async (socket: tls.TLSSocket, monitor: Monitor, limits: CheckLimits) => {
  if (!tlsLoginEnabled(monitor)) return null;
  try {
    await checkTlsLogin(socket, monitor, limits);
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};

/* Service credentials only travel over a connection whose certificate this
   monitor accepts: a chain the system trusts for the host name, or a
   certificate the operator accepted for this monitor by switching off chain
   validation or allowing self-signed certificates, and then only for the
   right host name. Anyone in the middle can present some certificate; without
   this check they would receive the password. */
export const tlsLoginAllowed = (
  monitor: Pick<Monitor, "validateCertificate" | "allowSelfSigned">,
  certificate: { authorized: boolean; hostnameMatch: boolean; selfSigned: boolean }
) => {
  if (certificate.authorized) return true;
  if (!certificate.hostnameMatch) return false;
  if (!monitor.validateCertificate) return true;
  return certificate.selfSigned && monitor.allowSelfSigned;
};

const skippedTlsLoginProblem = (monitor: Monitor) =>
  `${tlsLoginProtocol(monitor.type)?.toUpperCase() ?? "Service"} login was not attempted: the certificate is not trusted for ${monitor.sniHost || monitor.host}, so the credentials were not sent. Fix the certificate, or allow it for this monitor (self-signed certificates or no chain validation) if you trust this server.`;

const certificateKeyInfo = (x509: X509Certificate | null) => {
  const publicKey = x509?.publicKey;
  const details = publicKey?.asymmetricKeyDetails as { modulusLength?: number; namedCurve?: string } | undefined;
  return {
    keyType: publicKey?.asymmetricKeyType ?? null,
    keySize: details?.modulusLength ?? null,
    namedCurve: details?.namedCurve ?? null
  };
};

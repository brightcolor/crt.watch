import http from "node:http";
import https from "node:https";
import net from "node:net";
import nodemailer from "nodemailer";
import { env } from "../config/env.js";
import { addressPolicy, guardedLookup, literalAddress } from "../security/targets.js";
import type { SmtpSettings } from "../types.js";
import type { NetworkRule } from "../utils/networks.js";

/* Outbound connections for notifications: HTTP for webhook and chat channels,
   SMTP for email.

   The URLs and mail servers come from the people who configure channels and
   SMTP settings, and webhook URLs also from anonymous visitors who subscribe to
   a status page, so they are checked before anything is sent: only http and
   https for webhooks, and no private, loopback or link-local address for
   either. The check runs on the address the connection actually uses, after
   DNS, so a name that resolves to an internal address is refused as well, and
   so is every redirect target (see security/targets.ts). The operator can open
   internal networks again through ALLOW_PRIVATE_NOTIFICATION_TARGETS or
   NOTIFICATION_ALLOWED_NETWORKS. */

/** The target is not allowed by the operator's policy or is not a usable URL. */
export class NotificationTargetError extends Error {}

export type DeliverySettings = {
  allowPrivateTargets: boolean;
  allowedNetworks: NetworkRule[];
  maxRedirects: number;
  timeoutMs: number;
};

export type DeliveryRequest = {
  url: string;
  body: string;
  contentType: string;
  headers?: Record<string, string>;
};

export type DeliveryResult = { status: number; host: string };

export const deliverySettingsFromEnv = (): DeliverySettings => ({
  allowPrivateTargets: env.allowPrivateNotificationTargets,
  allowedNetworks: env.notificationAllowedNetworks,
  maxRedirects: env.notificationMaxRedirects,
  timeoutMs: env.notificationTimeoutSeconds * 1000
});

const redirectStatuses = new Set([301, 302, 303, 307, 308]);
const credentialHeaders = new Set(["authorization", "cookie", "proxy-authorization"]);
const bodyHeaders = new Set(["content-type", "content-length"]);

const blockedTarget = (host: string) =>
  new NotificationTargetError(`Notification target ${host} is a private, loopback or link-local address, and crt.watch does not send notifications into internal networks. Use a publicly reachable address, or ask the operator of this crt.watch instance to allow the network with NOTIFICATION_ALLOWED_NETWORKS or ALLOW_PRIVATE_NOTIFICATION_TARGETS.`);

const blockedMailServer = (host: string) =>
  new NotificationTargetError(`SMTP server ${host} is a private, loopback or link-local address, and crt.watch does not send notifications into internal networks. Use a publicly reachable mail server, or ask the operator of this crt.watch instance to allow the network with NOTIFICATION_ALLOWED_NETWORKS or ALLOW_PRIVATE_NOTIFICATION_TARGETS.`);

/** How the requests to one kind of target describe what went wrong, in the words of the people who configure it. */
export type TargetWording = {
  /** The configured address is not a URL, or a redirect points to something that is not one. */
  invalidUrl: (redirectedFrom?: URL) => Error;
  /** The address or a redirect uses a scheme other than http and https. */
  unsupportedScheme: (scheme: string, redirectedFrom?: URL) => Error;
  /** The address is outside the operator's policy. */
  refused: (host: string) => Error;
  timedOut: (host: string, seconds: number) => Error;
  tooManyRedirects: (host: string, limit: number) => Error;
  failed: (error: unknown, host: string) => Error;
};

const notificationWording: TargetWording = {
  invalidUrl: (from) => new NotificationTargetError(from
    ? `Notification endpoint ${from.hostname} redirected to an address that is not a valid URL. Use the final address of the endpoint.`
    : "Notification URL is not a valid address. Enter the full URL, for example https://hooks.example.com/notify."),
  unsupportedScheme: (scheme, from) => new NotificationTargetError(from
    ? `Notification endpoint ${from.hostname} redirected to an address with the scheme "${scheme}", which crt.watch does not follow. Use the final https:// address of the endpoint.`
    : "Notification URL must start with https:// or http://."),
  refused: blockedTarget,
  timedOut: (host, seconds) => new Error(`Notification endpoint ${host} did not answer within ${seconds} seconds. Check that it is reachable, or ask the operator to raise NOTIFICATION_TIMEOUT_SECONDS.`),
  tooManyRedirects: (host, limit) => new Error(`Notification endpoint ${host} redirected more than ${limit} times. Use the final address of the endpoint, or ask the operator to raise NOTIFICATION_MAX_REDIRECTS.`),
  failed: (error, host) => {
    if (error instanceof NotificationTargetError) return error;
    const code = (error as NodeJS.ErrnoException)?.code ?? "";
    if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new Error(`Notification target ${host} could not be resolved. Check the host name in the URL.`);
    if (code === "ECONNREFUSED") return new Error(`Notification endpoint ${host} refused the connection. Check the URL and port, and whether the service is running.`);
    if (code === "ECONNRESET" || code === "EPIPE") return new Error(`Notification endpoint ${host} closed the connection before answering. Try again later or check the endpoint.`);
    if (/CERT|SELF_SIGNED|ALTNAME|UNABLE_TO_VERIFY/i.test(code)) return new Error(`The TLS certificate of notification endpoint ${host} is not valid (${code}). Fix the certificate or use a different endpoint.`);
    return new Error(`Could not deliver the notification to ${host}: ${error instanceof Error ? error.message : String(error)}`);
  }
};

const parseTarget = (value: string, wording: TargetWording, base?: URL) => {
  let target: URL;
  try {
    target = new URL(value, base);
  } catch {
    throw wording.invalidUrl(base);
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") throw wording.unsupportedScheme(target.protocol.replace(/:$/, ""), base);
  return target;
};

type Hop = {
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
  isAllowed: (address: string) => boolean;
  deadline: number;
  timeoutMs: number;
  /** Bytes of the final answer's body to keep; 0 discards the body. */
  bodyLimit: number;
  followRedirects: boolean;
  wording: TargetWording;
};

type HopResponse = { status: number; location?: string; headers: http.IncomingHttpHeaders; body: string; bodyTruncated: boolean };

const sendOnce = (target: URL, hop: Hop) =>
  new Promise<HopResponse>((resolve, reject) => {
    const { method, headers, body } = hop;
    const transport = target.protocol === "https:" ? https : http;
    const timeout = hop.wording.timedOut(target.hostname, hop.timeoutMs / 1000);
    const request = transport.request(target, {
      method,
      headers: body === undefined ? headers : { ...headers, "content-length": String(Buffer.byteLength(body)) },
      lookup: guardedLookup(hop.isAllowed, hop.wording.refused),
      agent: false
    }, (response) => {
      const status = response.statusCode ?? 0;
      const location = response.headers.location;
      const answer = (text: string, bodyTruncated: boolean) => settle(() => resolve({ status, location, headers: response.headers, body: text, bodyTruncated }));
      response.on("error", (error) => settle(() => reject(hop.wording.failed(error, target.hostname))));
      // A redirect that is followed, and every answer whose body nobody reads, is discarded without being buffered.
      if (!hop.bodyLimit || (hop.followRedirects && redirectStatuses.has(status) && location)) {
        response.resume();
        return answer("", false);
      }
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        const room = hop.bodyLimit - size;
        if (chunk.length <= room) {
          chunks.push(chunk);
          size += chunk.length;
          return;
        }
        chunks.push(chunk.subarray(0, room));
        answer(Buffer.concat(chunks).toString("utf8"), true);
        response.destroy();
      });
      response.on("end", () => answer(Buffer.concat(chunks).toString("utf8"), false));
    });
    let settled = false;
    const settle = (finish: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      finish();
    };
    // The deadline covers the whole exchange, redirects and body included.
    const timer = setTimeout(() => {
      settle(() => reject(timeout));
      request.destroy(timeout);
    }, Math.max(1, hop.deadline - Date.now()));
    request.on("error", (error) => settle(() => reject(error === timeout ? timeout : hop.wording.failed(error, target.hostname))));
    request.end(body);
  });

export type TargetRequest = {
  url: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
  /** Follow redirects up to the limit of the settings; otherwise a redirect is the answer. */
  followRedirects: boolean;
  /** Bytes of the final answer's body to read; 0 discards the body. */
  bodyLimit: number;
};

export type TargetResponse = {
  status: number;
  /** Host and address of the final answer. */
  host: string;
  url: string;
  header: (name: string) => string | undefined;
  body: string;
  /** The body was longer than the limit; body holds its beginning. */
  bodyTruncated: boolean;
};

const withoutHeaders = (headers: Record<string, string>, names: Set<string>) =>
  Object.fromEntries(Object.entries(headers).filter(([name]) => !names.has(name.toLowerCase())));

const headerValue = (headers: http.IncomingHttpHeaders, name: string) => {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(", ") : value;
};

/**
 * Sends one request to an address that people configure and follows redirects
 * within the limit of the settings. The address and every redirect target pass
 * the target policy, on the address the connection uses. Used by webhook and
 * chat notifications and by HTTP monitors, each with its own settings and wording.
 */
export const requestTarget = async (request: TargetRequest, settings: DeliverySettings, wording: TargetWording): Promise<TargetResponse> => {
  const isAllowed = addressPolicy(settings);
  const deadline = Date.now() + settings.timeoutMs;
  let target = parseTarget(request.url, wording);
  let method: string = request.method;
  let body = request.body;
  let headers = request.headers;

  for (let redirects = 0; ; redirects += 1) {
    const literal = literalAddress(target.hostname);
    if (literal && !isAllowed(literal)) throw wording.refused(target.hostname);
    const response = await sendOnce(target, { method, headers, body, isAllowed, deadline, timeoutMs: settings.timeoutMs, bodyLimit: request.bodyLimit, followRedirects: request.followRedirects, wording });
    if (!request.followRedirects || !redirectStatuses.has(response.status) || !response.location) {
      return { status: response.status, host: target.hostname, url: target.href, header: (name) => headerValue(response.headers, name), body: response.body, bodyTruncated: response.bodyTruncated };
    }
    if (redirects >= settings.maxRedirects) throw wording.tooManyRedirects(target.hostname, settings.maxRedirects);
    const next = parseTarget(response.location, wording, target);
    // Credentials stay with the origin they were configured for.
    if (next.origin !== target.origin) headers = withoutHeaders(headers, credentialHeaders);
    // Same rule as fetch: 303, and 301/302 after a POST, continue as GET without the body.
    if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === "POST")) {
      method = "GET";
      body = undefined;
      headers = withoutHeaders(headers, bodyHeaders);
    }
    target = next;
  }
};

/**
 * Sends one notification request and follows redirects within the operator's limit.
 * Every hop is checked against the target policy. Resolves with the final HTTP status.
 */
export const postNotification = async (request: DeliveryRequest, settings: DeliverySettings = deliverySettingsFromEnv()): Promise<DeliveryResult> => {
  const response = await requestTarget({
    url: request.url,
    method: "POST",
    body: request.body,
    headers: { accept: "*/*", "user-agent": "crt.watch", ...request.headers, "content-type": request.contentType },
    followRedirects: true,
    bodyLimit: 0
  }, settings, notificationWording);
  return { status: response.status, host: response.host };
};

const describeMailFailure = (error: unknown, host: string, port: number) => {
  if (error instanceof NotificationTargetError) return error;
  const code = (error as NodeJS.ErrnoException)?.code ?? "";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new Error(`SMTP server ${host} could not be resolved. Check the host name in the SMTP settings.`);
  if (code === "ECONNREFUSED") return new Error(`SMTP server ${host} refused the connection on port ${port}. Check the host and port in the SMTP settings, and whether the mail server is running.`);
  if (code === "ECONNRESET" || code === "EPIPE") return new Error(`SMTP server ${host} closed the connection before answering. Try again later or check the mail server.`);
  if (code === "EHOSTUNREACH" || code === "ENETUNREACH") return new Error(`SMTP server ${host} is not reachable from crt.watch on port ${port}. Check the host and port in the SMTP settings and the network route to the mail server.`);
  return new Error(`Could not connect to SMTP server ${host} on port ${port}: ${error instanceof Error ? error.message : String(error)}. Check the SMTP settings.`);
};

/**
 * Opens the TCP connection to a mail server through the same address check as
 * webhook deliveries: every address the name resolves to must be allowed, and
 * the connection uses exactly those addresses. nodemailer receives the open
 * connection through getSocket and runs TLS or STARTTLS on it, checking the
 * certificate for the configured host name.
 */
export const connectMailServer = (host: string, port: number, settings: DeliverySettings = deliverySettingsFromEnv()) =>
  new Promise<net.Socket>((resolve, reject) => {
    const name = host.trim().replace(/^\[(.*)\]$/, "$1");
    if (!name) return reject(new NotificationTargetError("No SMTP server is configured. Enter the SMTP host in the SMTP settings or in the email channel."));
    const isAllowed = addressPolicy(settings);
    if (net.isIP(name) && !isAllowed(name)) return reject(blockedMailServer(name));
    const timeout = new Error(`SMTP server ${name} did not accept the connection on port ${port} within ${settings.timeoutMs / 1000} seconds. Check the host and port, or ask the operator to raise NOTIFICATION_TIMEOUT_SECONDS.`);
    const socket = net.connect({ host: name, port, lookup: guardedLookup(isAllowed, blockedMailServer) });
    const timer = setTimeout(() => socket.destroy(timeout), settings.timeoutMs);
    const fail = (error: Error) => {
      clearTimeout(timer);
      reject(error === timeout ? timeout : describeMailFailure(error, name, port));
    };
    socket.once("error", fail);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.off("error", fail);
      resolve(socket);
    });
  });

/** A nodemailer transport for these SMTP settings whose connections pass connectMailServer. */
export const mailTransport = (smtp: SmtpSettings, settings: DeliverySettings = deliverySettingsFromEnv()) => {
  const port = Number(smtp.port) || (smtp.secure ? 465 : 587);
  return nodemailer.createTransport({
    host: smtp.host,
    port,
    secure: smtp.secure,
    auth: smtp.username ? { user: smtp.username, pass: smtp.password } : undefined,
    requireTLS: smtp.starttls,
    getSocket: (_options, callback) => {
      connectMailServer(smtp.host, port, settings).then((connection) => callback(null, { connection }), (error: Error) => callback(error));
    }
  });
};

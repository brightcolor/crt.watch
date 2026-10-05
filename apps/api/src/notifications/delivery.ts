import dns, { type LookupAddress, type LookupOptions } from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import nodemailer from "nodemailer";
import { env } from "../config/env.js";
import type { SmtpSettings } from "../types.js";
import { isPublicAddress, networkMatcher, type NetworkRule } from "../utils/networks.js";

/* Outbound connections for notifications: HTTP for webhook and chat channels,
   SMTP for email.

   The URLs and mail servers come from the people who configure channels and
   SMTP settings, and webhook URLs also from anonymous visitors who subscribe to
   a status page, so they are checked before anything is sent: only http and
   https for webhooks, and no private, loopback or link-local address for
   either. The check runs on the address the connection actually uses, after
   DNS, so a name that resolves to an internal address is refused as well, and
   so is every redirect target. The operator can open internal networks again
   through ALLOW_PRIVATE_NOTIFICATION_TARGETS or NOTIFICATION_ALLOWED_NETWORKS. */

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

const addressPolicy = (settings: DeliverySettings) => {
  const inAllowedNetwork = networkMatcher(settings.allowedNetworks);
  return (address: string) => settings.allowPrivateTargets || isPublicAddress(address) || inAllowedNetwork(address);
};

const parseTarget = (value: string, base?: URL) => {
  let target: URL;
  try {
    target = new URL(value, base);
  } catch {
    throw new NotificationTargetError(base
      ? `Notification endpoint ${base.hostname} redirected to an address that is not a valid URL. Use the final address of the endpoint.`
      : "Notification URL is not a valid address. Enter the full URL, for example https://hooks.example.com/notify.");
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    throw new NotificationTargetError(base
      ? `Notification endpoint ${base.hostname} redirected to an address with the scheme "${target.protocol.replace(/:$/, "")}", which crt.watch does not follow. Use the final https:// address of the endpoint.`
      : "Notification URL must start with https:// or http://.");
  }
  return target;
};

const literalAddress = (target: URL) => {
  const host = target.hostname.replace(/^\[(.*)\]$/, "$1");
  return net.isIP(host) ? host : null;
};

// Resolves like dns.lookup, but refuses the connection when any resolved
// address is outside the policy. net.connect uses the address returned here,
// so the checked address is the one that is connected to.
const guardedLookup = (isAllowed: (address: string) => boolean, refuse: (host: string) => Error = blockedTarget) =>
  ((hostname: string, options: LookupOptions, callback: (error: NodeJS.ErrnoException | null, address?: string | LookupAddress[], family?: number) => void) => {
    dns.lookup(hostname, { ...options, all: true }, (error, addresses) => {
      if (error) return callback(error);
      const list = addresses as LookupAddress[];
      if (!list.length || list.some((entry) => !isAllowed(entry.address))) return callback(refuse(hostname));
      if (options.all) return callback(null, list);
      callback(null, list[0].address, list[0].family);
    });
  }) as unknown as net.LookupFunction;

const describeFailure = (error: unknown, host: string) => {
  if (error instanceof NotificationTargetError) return error;
  const code = (error as NodeJS.ErrnoException)?.code ?? "";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new Error(`Notification target ${host} could not be resolved. Check the host name in the URL.`);
  if (code === "ECONNREFUSED") return new Error(`Notification endpoint ${host} refused the connection. Check the URL and port, and whether the service is running.`);
  if (code === "ECONNRESET" || code === "EPIPE") return new Error(`Notification endpoint ${host} closed the connection before answering. Try again later or check the endpoint.`);
  if (/CERT|SELF_SIGNED|ALTNAME|UNABLE_TO_VERIFY/i.test(code)) return new Error(`The TLS certificate of notification endpoint ${host} is not valid (${code}). Fix the certificate or use a different endpoint.`);
  return new Error(`Could not deliver the notification to ${host}: ${error instanceof Error ? error.message : String(error)}`);
};

type HopResponse = { status: number; location?: string };

const sendOnce = (target: URL, method: string, headers: Record<string, string>, body: string | undefined, isAllowed: (address: string) => boolean, deadline: number, settings: DeliverySettings) =>
  new Promise<HopResponse>((resolve, reject) => {
    const transport = target.protocol === "https:" ? https : http;
    const timeout = new Error(`Notification endpoint ${target.hostname} did not answer within ${settings.timeoutMs / 1000} seconds. Check that it is reachable, or ask the operator to raise NOTIFICATION_TIMEOUT_SECONDS.`);
    const request = transport.request(target, {
      method,
      headers: body === undefined ? headers : { ...headers, "content-length": String(Buffer.byteLength(body)) },
      lookup: guardedLookup(isAllowed),
      agent: false
    }, (response) => {
      clearTimeout(timer);
      // Only the status matters; the body is discarded without being buffered.
      response.on("error", () => undefined);
      response.resume();
      resolve({ status: response.statusCode ?? 0, location: response.headers.location });
    });
    const timer = setTimeout(() => request.destroy(timeout), Math.max(1, deadline - Date.now()));
    request.on("error", (error) => {
      clearTimeout(timer);
      reject(error === timeout ? timeout : describeFailure(error, target.hostname));
    });
    request.end(body);
  });

/**
 * Sends one notification request and follows redirects within the operator's limit.
 * Every hop is checked against the target policy. Resolves with the final HTTP status.
 */
export const postNotification = async (request: DeliveryRequest, settings: DeliverySettings = deliverySettingsFromEnv()): Promise<DeliveryResult> => {
  const isAllowed = addressPolicy(settings);
  const deadline = Date.now() + settings.timeoutMs;
  let target = parseTarget(request.url);
  let method = "POST";
  let body: string | undefined = request.body;
  let headers: Record<string, string> = { accept: "*/*", "user-agent": "crt.watch", ...request.headers, "content-type": request.contentType };

  for (let redirects = 0; ; redirects += 1) {
    const literal = literalAddress(target);
    if (literal && !isAllowed(literal)) throw blockedTarget(target.hostname);
    const response = await sendOnce(target, method, headers, body, isAllowed, deadline, settings);
    if (!redirectStatuses.has(response.status) || !response.location) return { status: response.status, host: target.hostname };
    if (redirects >= settings.maxRedirects) {
      throw new Error(`Notification endpoint ${target.hostname} redirected more than ${settings.maxRedirects} times. Use the final address of the endpoint, or ask the operator to raise NOTIFICATION_MAX_REDIRECTS.`);
    }
    const next = parseTarget(response.location, target);
    // Credentials stay with the origin they were configured for.
    if (next.origin !== target.origin) headers = Object.fromEntries(Object.entries(headers).filter(([name]) => !credentialHeaders.has(name.toLowerCase())));
    // Same rule as fetch: 303, and 301/302 after a POST, continue as GET without the body.
    if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === "POST")) {
      method = "GET";
      body = undefined;
      headers = Object.fromEntries(Object.entries(headers).filter(([name]) => !bodyHeaders.has(name.toLowerCase())));
    }
    target = next;
  }
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

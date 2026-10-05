import dns, { type LookupAddress, type LookupOptions } from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { env } from "../config/env.js";
import { isPublicAddress, networkMatcher, type NetworkRule } from "../utils/networks.js";

/* Outbound HTTP for webhook and chat notifications.

   The URLs come from the people who configure channels and from anonymous
   visitors who subscribe to a status page, so they are checked before anything
   is sent: only http and https, and no private, loopback or link-local address.
   The check runs on the address the connection actually uses, after DNS, so a
   name that resolves to an internal address is refused as well, and so is every
   redirect target. The operator can open internal networks again through
   ALLOW_PRIVATE_NOTIFICATION_TARGETS or NOTIFICATION_ALLOWED_NETWORKS. */

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
const guardedLookup = (isAllowed: (address: string) => boolean) =>
  ((hostname: string, options: LookupOptions, callback: (error: NodeJS.ErrnoException | null, address?: string | LookupAddress[], family?: number) => void) => {
    dns.lookup(hostname, { ...options, all: true }, (error, addresses) => {
      if (error) return callback(error);
      const list = addresses as LookupAddress[];
      if (!list.length || list.some((entry) => !isAllowed(entry.address))) return callback(blockedTarget(hostname));
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

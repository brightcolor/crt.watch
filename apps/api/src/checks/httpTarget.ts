import { env } from "../config/env.js";
import { requestTarget, type DeliverySettings, type TargetRequest, type TargetWording } from "../notifications/delivery.js";
import type { Monitor } from "../types.js";
import { MonitorTargetError, monitorTargetPolicy, refusedMonitorTarget } from "./validation.js";

/* HTTP and HTTP login monitors send their request through the same guarded
   client as webhook notifications (notifications/delivery.ts). The target and
   every redirect target pass the monitor target policy on the address that is
   connected to, redirects end after MONITOR_MAX_REDIRECTS, the monitor's
   timeout covers the whole exchange, and a body is read up to
   MONITOR_HTTP_BODY_LIMIT_KB. */

const monitorWording: TargetWording = {
  invalidUrl: (from) => new Error(from
    ? `${from.host} redirected to an address that is not a valid URL. Point the monitor at the final address.`
    : "The address of this monitor is not a valid URL. Check its host, port and path."),
  unsupportedScheme: (scheme, from) => new Error(from
    ? `${from.host} redirected to an address with the scheme "${scheme}", which crt.watch does not follow. Point the monitor at the final address.`
    : `The monitor uses the scheme "${scheme}". Set its scheme to http or https.`),
  refused: refusedMonitorTarget,
  timedOut: (host, seconds) => new Error(`${host} did not answer within ${seconds} seconds. Check that the service is reachable, or raise the timeout of the monitor.`),
  tooManyRedirects: (host, limit) => new Error(`${host} redirected more than ${limit} times. Point the monitor at the final address, or ask the operator to raise MONITOR_MAX_REDIRECTS.`),
  failed: (error, host) => {
    if (error instanceof MonitorTargetError) return error;
    const code = (error as NodeJS.ErrnoException)?.code ?? "";
    if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new Error(`${host} could not be resolved. Check the host name of the monitor.`);
    if (code === "ECONNREFUSED") return new Error(`${host} refused the connection. Check the port of the monitor and whether the service is running.`);
    if (code === "ECONNRESET" || code === "EPIPE") return new Error(`${host} closed the connection before answering. Try again later or check the service.`);
    if (/CERT|SELF_SIGNED|ALTNAME|UNABLE_TO_VERIFY/i.test(code)) return new Error(`The TLS certificate of ${host} is not valid (${code}), so the HTTP request was not sent. The TLS details of this monitor name the problem.`);
    return new Error(`The HTTP request to ${host} failed: ${error instanceof Error ? error.message : String(error)}`);
  }
};

export type MonitorHttpSettings = DeliverySettings & { bodyLimitBytes: number };

export const monitorHttpSettings = (monitor: Pick<Monitor, "timeoutSeconds">): MonitorHttpSettings => ({
  ...monitorTargetPolicy(),
  maxRedirects: env.monitorMaxRedirects,
  timeoutMs: monitor.timeoutSeconds * 1000,
  bodyLimitBytes: env.monitorHttpBodyLimitKb * 1024
});

/** The request of an HTTP monitor; readBody asks for the body of the final answer, up to the limit. */
export type MonitorHttpRequest = Omit<TargetRequest, "bodyLimit"> & { readBody: boolean };

export const requestMonitorUrl = (request: MonitorHttpRequest, settings: MonitorHttpSettings) => {
  const { readBody, ...rest } = request;
  return requestTarget({
    ...rest,
    headers: { accept: "*/*", "user-agent": "crt.watch", ...rest.headers },
    bodyLimit: readBody ? settings.bodyLimitBytes : 0
  }, settings, monitorWording);
};

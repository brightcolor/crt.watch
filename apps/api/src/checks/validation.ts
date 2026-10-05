import net from "node:net";
import { env } from "../config/env.js";
import { addressPolicy, guardedLookup, literalAddress, type TargetPolicy } from "../security/targets.js";

const hostnamePattern = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9*.-]+(?<!-)$/;

/* Monitors connect to the hosts that their organization enters. While
   ALLOW_PRIVATE_TARGETS is off, a check reaches public addresses only, plus the
   networks listed in MONITOR_ALLOWED_NETWORKS. The ranges and the check are the
   same as for notifications (security/targets.ts): an IP address is checked
   when the monitor is saved and before every check, a host name on every
   address it resolves to, inside the lookup of each connection the check opens. */

/** The monitor target is outside the operator's policy. */
export class MonitorTargetError extends Error {}

export const monitorTargetPolicy = (): TargetPolicy => ({
  allowPrivateTargets: env.allowPrivateTargets,
  allowedNetworks: env.monitorAllowedNetworks
});

export const refusedMonitorTarget = (host: string) =>
  new MonitorTargetError(`Monitor target ${host} points to a private, loopback or link-local address, and this crt.watch instance checks public addresses only. Use a publicly reachable host, or ask the operator of this crt.watch instance to allow the network with MONITOR_ALLOWED_NETWORKS or ALLOW_PRIVATE_TARGETS.`);

export const validateHost = (host: string) => {
  const clean = host.trim().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  if (!clean || clean.length > 253) throw new Error("Host is required and must be shorter than 254 characters.");
  if (!hostnamePattern.test(clean) && net.isIP(clean) === 0) throw new Error("Host must be a valid hostname or IP address, such as mail.example.com or 203.0.113.10.");
  const literal = literalAddress(clean);
  if (literal && !addressPolicy(monitorTargetPolicy())(literal)) throw refusedMonitorTarget(clean);
  return clean.toLowerCase();
};

export const validatePort = (port: number) => {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Port must be between 1 and 65535.");
  return port;
};

/** Socket options for every connection of a check: the address that is connected to passes the monitor target policy. */
export const monitorConnectOptions = (policy: TargetPolicy = monitorTargetPolicy()) => ({
  lookup: guardedLookup(addressPolicy(policy), refusedMonitorTarget)
});

/**
 * Checks a monitor target before a check connects: an IP address directly, a
 * host name on every address it resolves to. The connections of the check
 * repeat the check on the address they use (monitorConnectOptions).
 */
export const assertAllowedTarget = (host: string, policy: TargetPolicy = monitorTargetPolicy()) =>
  new Promise<void>((resolve, reject) => {
    const literal = literalAddress(host);
    if (literal) return addressPolicy(policy)(literal) ? resolve() : reject(refusedMonitorTarget(host));
    if (policy.allowPrivateTargets) return resolve();
    monitorConnectOptions(policy).lookup(host, { all: true }, (error) => (error ? reject(error) : resolve()));
  });

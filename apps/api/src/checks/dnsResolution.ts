import dns from "node:dns/promises";
import net from "node:net";
import { env } from "../config/env.js";
import { addressPolicy } from "../security/targets.js";
import type { CheckResult, DnsResolutionSummary, DnsResolverCheck, Monitor } from "../types.js";
import { nowIso } from "../utils/time.js";
import { monitorTargetPolicy } from "./validation.js";

const publicResolvers = [
  { name: "Cloudflare", servers: ["1.1.1.1", "1.0.0.1"] },
  { name: "Quad9", servers: ["9.9.9.9", "149.112.112.112"] },
  { name: "Google", servers: ["8.8.8.8", "8.8.4.4"] }
];

export const enrichWithDnsResolution = async (
  monitor: Monitor,
  result: CheckResult,
  previous?: CheckResult
): Promise<CheckResult> => {
  if (monitor.config?.dnsCheckEnabled === false) return result;
  try {
    return { ...result, dns: await inspectDnsResolution(monitor.host, monitor.timeoutSeconds * 1000) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ...result,
      dns: dnsSummary(monitor.host, [], [], [{ name: "System", kind: "system", servers: [], addresses: [], error: message }], [message])
    };
  }
};

export const shouldRunDnsResolution = (_monitor: Pick<Monitor, "config">, _previous?: Pick<CheckResult, "dns">) => true;

export const dnsChanged = (current?: DnsResolutionSummary | null, previous?: DnsResolutionSummary | null) =>
  Boolean(current?.fresh && previous?.fingerprint && current.fingerprint !== previous.fingerprint);

export const inspectDnsResolution = async (host: string, timeoutMs = 10_000): Promise<DnsResolutionSummary> => {
  if (net.isIP(host)) return dnsSummary(host, [host], [], [check("Literal IP", "system", [], [host])], []);
  const system = await systemLookup(host, timeoutMs);
  const authoritative = await authoritativeLookup(host, timeoutMs);
  const publics = await Promise.all(publicResolvers.map((resolver) => resolverLookup(host, resolver.name, "public", resolver.servers, timeoutMs)));
  const checks = [system, authoritative.check, ...publics].filter(Boolean) as DnsResolverCheck[];
  const authoritativeNameservers = authoritative.nameservers;
  const addresses = system.addresses.length ? system.addresses : firstAddresses(checks);
  return dnsSummary(host, addresses, authoritativeNameservers, checks, compareDnsAnswers(authoritative.check, publics), authoritative.zone);
};

export const compareDnsAnswers = (authoritative: DnsResolverCheck | null, publics: DnsResolverCheck[]) => {
  const mismatches: string[] = [];
  if (authoritative?.addresses.length) {
    for (const item of publics.filter((entry) => entry.addresses.length)) {
      if (!sameSet(authoritative.addresses, item.addresses)) {
        mismatches.push(`${item.name} differs from authoritative DNS (${format(item.addresses)} vs ${format(authoritative.addresses)}).`);
      }
    }
  }
  const publicFingerprints = new Set(publics.filter((item) => item.addresses.length).map((item) => item.addresses.join(",")));
  if (publicFingerprints.size > 1) mismatches.push("Public resolvers returned different address sets.");
  return mismatches;
};

const systemLookup = async (host: string, timeoutMs: number) => {
  const records = await withTimeout(dns.lookup(host, { all: true, verbatim: true }), timeoutMs, "System DNS lookup timed out.");
  return check("System resolver", "system", [], unique(records.map((record) => record.address)));
};

const authoritativeLookup = async (host: string, timeoutMs: number) => {
  const zone = await findAuthoritativeZone(host, timeoutMs);
  if (!zone) return { zone: null, nameservers: [], check: check("Authoritative DNS", "authoritative", [], [], "No authoritative nameservers found.") };
  const { queried, refused } = await resolveNameserverAddresses(zone.nameservers, timeoutMs);
  if (!queried.length) return { ...zone, check: check("Authoritative DNS", "authoritative", zone.nameservers, [], refused.length ? refusedNameservers(zone.zone, refused) : unresolvedNameservers(zone.zone)) };
  const result = await resolverLookup(host, "Authoritative DNS", "authoritative", queried, timeoutMs);
  return { ...zone, check: { ...result, servers: zone.nameservers } };
};

const unresolvedNameservers = (zone: string) =>
  `The addresses of the authoritative nameservers of ${zone} could not be resolved, so the comparison with authoritative DNS is skipped. Check the NS records of ${zone}.`;

const refusedNameservers = (zone: string, addresses: string[]) =>
  `The authoritative nameservers of ${zone} resolve only to private, loopback or link-local addresses (${format(addresses)}), and this crt.watch instance sends DNS queries to public addresses only, so the comparison with authoritative DNS is skipped. To include it, ask the operator of this crt.watch instance to allow these addresses with MONITOR_ALLOWED_NETWORKS or ALLOW_PRIVATE_TARGETS.`;

const findAuthoritativeZone = async (host: string, timeoutMs: number) => {
  const labels = host.replace(/\.$/, "").split(".");
  for (let index = 0; index < labels.length - 1; index += 1) {
    const zone = labels.slice(index).join(".");
    try {
      const nameservers = await withTimeout(dns.resolveNs(zone), timeoutMs, "NS lookup timed out.");
      if (nameservers.length) return { zone, nameservers: nameservers.sort() };
    } catch {
      // Walk up until a delegated zone is found.
    }
  }
  return null;
};

/* The nameservers come from the NS records of the monitored zone. Like every
   other address a check reaches, their addresses pass the monitor target check
   before a query goes out, with the same settings (ALLOW_PRIVATE_TARGETS,
   MONITOR_ALLOWED_NETWORKS; see validation.ts). The first
   MONITOR_DNS_NAMESERVER_LIMIT nameservers are resolved, and up to
   MONITOR_DNS_NAMESERVER_ADDRESS_LIMIT of their addresses that pass are
   queried. */
const resolveNameserverAddresses = async (nameservers: string[], timeoutMs: number) => {
  const records = await Promise.all(nameservers.slice(0, env.monitorDnsNameserverLimit).map(async (server) => {
    try {
      return await resolveIps(dns, server, timeoutMs);
    } catch {
      return [];
    }
  }));
  const allowed = addressPolicy(monitorTargetPolicy());
  const addresses = unique(records.flat());
  return {
    queried: addresses.filter(allowed).slice(0, env.monitorDnsNameserverAddressLimit),
    refused: addresses.filter((address) => !allowed(address))
  };
};

const resolverLookup = async (host: string, name: string, kind: DnsResolverCheck["kind"], servers: string[], timeoutMs: number) => {
  const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 1 });
  resolver.setServers(servers);
  try {
    return check(name, kind, servers, await resolveIps(resolver, host, timeoutMs));
  } catch (error) {
    return check(name, kind, servers, [], error instanceof Error ? error.message : String(error));
  }
};

const resolveIps = async (resolver: Pick<typeof dns, "resolve4" | "resolve6">, host: string, timeoutMs: number) => {
  const [a, aaaa] = await Promise.all([safeResolve(() => resolver.resolve4(host), timeoutMs), safeResolve(() => resolver.resolve6(host), timeoutMs)]);
  return unique([...a, ...aaaa]);
};

const safeResolve = async (run: () => Promise<string[]>, timeoutMs: number) => {
  try {
    return await withTimeout(run(), timeoutMs, "DNS query timed out.");
  } catch {
    return [];
  }
};

const dnsSummary = (host: string, addresses: string[], nameservers: string[], checks: DnsResolverCheck[], mismatches: string[], zone?: string | null): DnsResolutionSummary => ({
  host,
  checkedAt: nowIso(),
  fresh: true,
  addresses: unique(addresses),
  authoritativeZone: zone ?? null,
  authoritativeNameservers: nameservers,
  checks,
  mismatches,
  fingerprint: JSON.stringify({ addresses: unique(addresses), mismatches, checks: checks.map(({ name, addresses, error }) => ({ name, addresses, error: error ?? "" })) })
});

const check = (name: string, kind: DnsResolverCheck["kind"], servers: string[], addresses: string[], error?: string): DnsResolverCheck => ({
  name,
  kind,
  servers,
  addresses: unique(addresses),
  error: error ?? null
});

const withTimeout = async <T>(promise: Promise<T>, timeoutMs: number, message: string) => {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs); })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
};

const firstAddresses = (checks: DnsResolverCheck[]) => checks.find((item) => item.addresses.length)?.addresses ?? [];
const sameSet = (left: string[], right: string[]) => left.length === right.length && left.every((value, index) => value === right[index]);
const unique = (values: string[]) => [...new Set(values.filter(Boolean))].sort();
const format = (values: string[]) => values.join(", ") || "none";

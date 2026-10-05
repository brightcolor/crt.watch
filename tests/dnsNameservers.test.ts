import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/* The DNS details query the authoritative nameservers of a monitored zone
   only on addresses that pass the monitor target check, with the settings of
   the monitors: ALLOW_PRIVATE_TARGETS and MONITOR_ALLOWED_NETWORKS. */

const zone = vi.hoisted(() => ({
  nameservers: new Map<string, string[]>(),
  addresses: new Map<string, string[]>(),
  resolvedNames: [] as string[],
  queriedServers: [] as string[][]
}));

vi.mock("node:dns/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns/promises")>();
  const notFound = (name: string) => Object.assign(new Error(`queryA ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  const ipv4 = (name: string) => (zone.addresses.get(name) ?? []).filter((address) => !address.includes(":"));
  const ipv6 = (name: string) => (zone.addresses.get(name) ?? []).filter((address) => address.includes(":"));
  class Resolver {
    setServers(servers: string[]) {
      zone.queriedServers.push([...servers]);
    }
    async resolve4(name: string) {
      return ipv4(name);
    }
    async resolve6(name: string) {
      return ipv6(name);
    }
  }
  const fake = {
    ...actual,
    Resolver,
    lookup: async (name: string) => ipv4(name).map((address) => ({ address, family: 4 })),
    resolveNs: async (name: string) => {
      const servers = zone.nameservers.get(name);
      if (!servers) throw notFound(name);
      return [...servers];
    },
    resolve4: async (name: string) => {
      zone.resolvedNames.push(name);
      if (!zone.addresses.has(name)) throw notFound(name);
      return ipv4(name);
    },
    resolve6: async (name: string) => ipv6(name)
  };
  return { ...fake, default: fake };
});

import { inspectDnsResolution } from "../apps/api/src/checks/dnsResolution.js";
import { env } from "../apps/api/src/config/env.js";
import { parseNetworkList } from "../apps/api/src/utils/networks.js";

const defaults = {
  allowPrivateTargets: env.allowPrivateTargets,
  monitorAllowedNetworks: env.monitorAllowedNetworks,
  monitorDnsNameserverLimit: env.monitorDnsNameserverLimit,
  monitorDnsNameserverAddressLimit: env.monitorDnsNameserverAddressLimit
};

// Addresses outside the special-purpose registries, so the target check treats them as public.
const publicNameserver = "93.184.216.34";
const secondPublicNameserver = "93.184.216.35";
const publicResolvers = ["1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "8.8.8.8", "8.8.4.4"];

const authoritative = async (host = "www.example.org") => {
  const summary = await inspectDnsResolution(host, 1000);
  return summary.checks.find((check) => check.kind === "authoritative")!;
};

/** The servers of every query that went to authoritative nameservers. */
const authoritativeQueries = () => zone.queriedServers.filter((servers) => !servers.every((server) => publicResolvers.includes(server)));

beforeEach(() => {
  zone.nameservers.clear();
  zone.addresses.clear();
  zone.resolvedNames.length = 0;
  zone.queriedServers.length = 0;
  zone.addresses.set("www.example.org", ["93.184.216.80"]);
});

afterEach(() => {
  Object.assign(env, defaults);
});

describe("authoritative nameservers", () => {
  it("on private addresses only get no query, and the DNS details say what to allow", async () => {
    zone.nameservers.set("example.org", ["ns1.example.org", "ns2.example.org"]);
    zone.addresses.set("ns1.example.org", ["10.0.0.53"]);
    zone.addresses.set("ns2.example.org", ["fd00::53"]);

    const check = await authoritative();

    expect(authoritativeQueries()).toEqual([]);
    expect(check).toMatchObject({ servers: ["ns1.example.org", "ns2.example.org"], addresses: [] });
    expect(check.error).toBe(
      "The authoritative nameservers of example.org resolve only to private, loopback or link-local addresses (10.0.0.53, fd00::53), and this crt.watch instance sends DNS queries to public addresses only, so the comparison with authoritative DNS is skipped. To include it, ask the operator of this crt.watch instance to allow these addresses with MONITOR_ALLOWED_NETWORKS or ALLOW_PRIVATE_TARGETS."
    );
  });

  it("on public addresses get the query, and private addresses of the same zone stay out of it", async () => {
    zone.nameservers.set("example.org", ["ns1.example.org", "ns2.example.org"]);
    zone.addresses.set("ns1.example.org", ["10.0.0.53", "127.0.0.53"]);
    zone.addresses.set("ns2.example.org", [publicNameserver]);

    const check = await authoritative();

    expect(authoritativeQueries()).toEqual([[publicNameserver]]);
    expect(check).toMatchObject({ addresses: ["93.184.216.80"], error: null });
  });

  it("in MONITOR_ALLOWED_NETWORKS get the query", async () => {
    env.monitorAllowedNetworks = parseNetworkList("10.0.0.0/24", "MONITOR_ALLOWED_NETWORKS");
    zone.nameservers.set("example.org", ["ns1.example.org"]);
    zone.addresses.set("ns1.example.org", ["10.0.0.53", "10.0.1.53"]);

    const check = await authoritative();

    expect(authoritativeQueries()).toEqual([["10.0.0.53"]]);
    expect(check.error).toBeNull();
  });

  it("on private addresses get the query with ALLOW_PRIVATE_TARGETS", async () => {
    env.allowPrivateTargets = true;
    zone.nameservers.set("example.org", ["ns1.example.org"]);
    zone.addresses.set("ns1.example.org", ["10.0.0.53"]);

    await authoritative();

    expect(authoritativeQueries()).toEqual([["10.0.0.53"]]);
  });

  it("are resolved up to MONITOR_DNS_NAMESERVER_LIMIT and queried on up to MONITOR_DNS_NAMESERVER_ADDRESS_LIMIT addresses", async () => {
    zone.nameservers.set("example.org", ["ns1.example.org", "ns2.example.org", "ns3.example.org"]);
    zone.addresses.set("ns1.example.org", ["10.0.0.53", publicNameserver, secondPublicNameserver]);
    zone.addresses.set("ns2.example.org", ["93.184.216.36"]);
    zone.addresses.set("ns3.example.org", ["93.184.216.37"]);

    await authoritative();
    expect(authoritativeQueries()).toEqual([[publicNameserver, secondPublicNameserver, "93.184.216.36", "93.184.216.37"]]);

    env.monitorDnsNameserverLimit = 1;
    env.monitorDnsNameserverAddressLimit = 1;
    zone.resolvedNames.length = 0;
    zone.queriedServers.length = 0;

    await authoritative();
    expect(zone.resolvedNames.filter((name) => name.startsWith("ns"))).toEqual(["ns1.example.org"]);
    expect(authoritativeQueries()).toEqual([[publicNameserver]]);
  });

  it("whose addresses cannot be resolved leave a message that names the zone", async () => {
    zone.nameservers.set("example.org", ["ns1.example.org"]);

    const check = await authoritative();

    expect(authoritativeQueries()).toEqual([]);
    expect(check.error).toBe("The addresses of the authoritative nameservers of example.org could not be resolved, so the comparison with authoritative DNS is skipped. Check the NS records of example.org.");
  });
});

import dns, { type LookupAddress, type LookupOptions } from "node:dns";
import net from "node:net";
import { isPublicAddress, networkMatcher, type NetworkRule } from "../utils/networks.js";

/* Connections to addresses that people configure in crt.watch: webhook and
   chat notifications, SMTP servers and the targets of monitors. The operator's
   policy decides which addresses such a connection may reach. The check runs
   on the address the connection actually uses, after DNS: an IP address is
   checked before connecting, a host name inside the lookup of the connection,
   so the address that passed is the one that is connected to. */

export type TargetPolicy = {
  /** true lets every address through, as on an instance where every user is trusted. */
  allowPrivateTargets: boolean;
  /** Internal addresses and networks that stay reachable while internal targets are blocked. */
  allowedNetworks: NetworkRule[];
};

/** Returns the check for single IP addresses under the policy. */
export const addressPolicy = (policy: TargetPolicy) => {
  const inAllowedNetwork = networkMatcher(policy.allowedNetworks);
  return (address: string) => policy.allowPrivateTargets || isPublicAddress(address) || inAllowedNetwork(address);
};

/** The IP address a host is written as, without the brackets of an IPv6 address; null for a host name. */
export const literalAddress = (host: string) => {
  const bare = host.replace(/^\[(.*)\]$/, "$1");
  return net.isIP(bare) ? bare : null;
};

/**
 * A lookup function for net.connect, tls.connect and http.request: it resolves
 * like dns.lookup and refuses the connection with the error from refuse when
 * any address of the name is outside the policy.
 */
export const guardedLookup = (isAllowed: (address: string) => boolean, refuse: (host: string) => Error) =>
  ((hostname: string, options: LookupOptions, callback: (error: NodeJS.ErrnoException | null, address?: string | LookupAddress[], family?: number) => void) => {
    dns.lookup(hostname, { ...options, all: true }, (error, addresses) => {
      if (error) return callback(error);
      const list = addresses as LookupAddress[];
      if (!list.length || list.some((entry) => !isAllowed(entry.address))) return callback(refuse(hostname));
      if (options.all) return callback(null, list);
      callback(null, list[0].address, list[0].family);
    });
  }) as unknown as net.LookupFunction;

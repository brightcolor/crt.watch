import net from "node:net";

export type NetworkRule = { address: string; prefix: number; type: "ipv4" | "ipv6" };

/* Address ranges that are not reachable on the public internet, after the IANA
   special-purpose address registries (RFC 6890 and its successors). A request
   aimed at one of them stays inside the network crt.watch runs in: loopback,
   private networks, link-local (including the cloud metadata endpoint at
   169.254.169.254), carrier-grade NAT, multicast and reserved space. The list
   follows the registry, so it is not a setting; NOTIFICATION_ALLOWED_NETWORKS
   opens individual ranges again. */
const specialPurposeRanges: NetworkRule[] = [
  { address: "0.0.0.0", prefix: 8, type: "ipv4" },
  { address: "10.0.0.0", prefix: 8, type: "ipv4" },
  { address: "100.64.0.0", prefix: 10, type: "ipv4" },
  { address: "127.0.0.0", prefix: 8, type: "ipv4" },
  { address: "169.254.0.0", prefix: 16, type: "ipv4" },
  { address: "172.16.0.0", prefix: 12, type: "ipv4" },
  { address: "192.0.0.0", prefix: 24, type: "ipv4" },
  { address: "192.0.2.0", prefix: 24, type: "ipv4" },
  { address: "192.88.99.0", prefix: 24, type: "ipv4" },
  { address: "192.168.0.0", prefix: 16, type: "ipv4" },
  { address: "198.18.0.0", prefix: 15, type: "ipv4" },
  { address: "198.51.100.0", prefix: 24, type: "ipv4" },
  { address: "203.0.113.0", prefix: 24, type: "ipv4" },
  { address: "224.0.0.0", prefix: 4, type: "ipv4" },
  { address: "240.0.0.0", prefix: 4, type: "ipv4" },
  { address: "::", prefix: 128, type: "ipv6" },
  { address: "::1", prefix: 128, type: "ipv6" },
  { address: "64:ff9b:1::", prefix: 48, type: "ipv6" },
  { address: "100::", prefix: 64, type: "ipv6" },
  { address: "2001:db8::", prefix: 32, type: "ipv6" },
  { address: "fc00::", prefix: 7, type: "ipv6" },
  { address: "fe80::", prefix: 10, type: "ipv6" },
  { address: "fec0::", prefix: 10, type: "ipv6" },
  { address: "ff00::", prefix: 8, type: "ipv6" }
];

// NAT64 gateways reach IPv4 hosts through 64:ff9b::/96 (RFC 6052), so the IPv4
// ranges above are blocked in that form as well. IPv4-mapped IPv6 addresses
// (::ffff:a.b.c.d) are matched against the IPv4 ranges by BlockList itself.
const nat64Ranges: NetworkRule[] = specialPurposeRanges
  .filter((rule) => rule.type === "ipv4")
  .map((rule) => ({ address: `64:ff9b::${rule.address}`, prefix: 96 + rule.prefix, type: "ipv6" }));

const addressType = (address: string) => (net.isIP(address) === 6 ? "ipv6" : "ipv4");
const withoutZone = (address: string) => address.split("%")[0];

const blockListOf = (rules: NetworkRule[]) => {
  const list = new net.BlockList();
  for (const rule of rules) list.addSubnet(rule.address, rule.prefix, rule.type);
  return list;
};

const specialPurpose = blockListOf([...specialPurposeRanges, ...nat64Ranges]);

/** True for an IP address that is routable on the public internet. */
export const isPublicAddress = (value: string) => {
  const address = withoutZone(value.trim());
  return Boolean(net.isIP(address)) && !specialPurpose.check(address, addressType(address));
};

/** Returns a matcher for the given networks; an empty list matches nothing. */
export const networkMatcher = (rules: NetworkRule[]) => {
  const list = blockListOf(rules);
  return (value: string) => {
    const address = withoutZone(value.trim());
    return Boolean(rules.length && net.isIP(address) && list.check(address, addressType(address)));
  };
};

/**
 * Parses a list of IP addresses and networks such as "192.168.10.5, 10.20.0.0/16, fd00::/8".
 * Throws an error that names the setting and the entry it could not read.
 */
export const parseNetworkList = (value: string, settingName: string): NetworkRule[] =>
  value.split(/[\s,]+/).filter(Boolean).map((entry) => {
    const [address, prefixText, ...rest] = entry.split("/");
    const family = net.isIP(address);
    const maxPrefix = family === 6 ? 128 : 32;
    const prefix = prefixText === undefined ? maxPrefix : /^\d{1,3}$/.test(prefixText) ? Number(prefixText) : Number.NaN;
    if (!family || rest.length || !Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
      throw new Error(`${settingName} contains "${entry}", which is neither an IP address nor a network. Use entries such as 192.168.10.5 or 10.20.0.0/16, separated by commas.`);
    }
    return { address, prefix, type: family === 6 ? "ipv6" : "ipv4" };
  });

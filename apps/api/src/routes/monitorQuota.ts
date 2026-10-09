import { monitors, tenants } from "../storage/repositories.js";

/* An organization holds at most as many monitors as its monitor limit allows;
   a limit of 0 or less means no limit. Every way of creating monitors counts
   against it: the form, cloning, the bulk, discovery and JSON imports, and
   restores. */

export type MonitorQuota = { limit: number; left: number };

/** The organization's monitor limit and how many more monitors it may create; without a limit, left is Infinity. */
export const monitorQuota = (tenantId: string): MonitorQuota => {
  const limit = tenants.get(tenantId)?.monitorLimit ?? 0;
  return { limit, left: limit > 0 ? Math.max(0, limit - monitors.count(tenantId)) : Number.POSITIVE_INFINITY };
};

const monitorCount = (count: number) => `${count} monitor${count === 1 ? "" : "s"}`;
const raiseLimit = "ask the operator of this crt.watch instance to raise the limit";

/** The answer when the organization has no room for another monitor. */
export const monitorLimitReached = ({ limit }: MonitorQuota) =>
  `This organization has reached its limit of ${monitorCount(limit)}. Delete monitors it no longer needs, or ${raiseLimit}.`;

/** The answer when an import or a backup holds more monitors than the organization has room for. */
export const monitorsBeyondLimit = (requested: number, { limit, left }: MonitorQuota, source: "import" | "backup") => {
  const nextStep = source === "import"
    ? "Import fewer monitors or delete monitors it no longer needs"
    : "Remove monitors from the backup or delete monitors the organization no longer needs, then restore again";
  return `This ${source} holds ${monitorCount(requested)}, and the organization has room for ${left} more within its limit of ${monitorCount(limit)}. ${nextStep}, or ${raiseLimit}.`;
};

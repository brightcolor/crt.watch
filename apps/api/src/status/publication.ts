import { z } from "zod";
import { appSettings, monitors, tenants } from "../storage/repositories.js";
import { DEFAULT_TENANT_ID } from "../types.js";
import type { Monitor, StatusPageConfig, StatusPageSettings, StatusSubscription, Tenant } from "../types.js";
import { id } from "../utils/id.js";

/* What the public may see.

   An organization publishes monitors through its status pages (Operations,
   Status pages). An enabled page shows the monitors of its organization that
   carry all of the page's labels; a page without labels shows all of them.
   Nothing else is public. The public status pages, the badges and the status
   page subscriptions all ask this module, so they agree on it:

   - a page answers under its slug, which is unique across organizations, and
     under its labels joined with "+", as in /public/status/prod+mail;
   - when several organizations publish the same labels, the label address
     belongs to the default organization, then to the oldest one, so it always
     resolves the same way; the slug address reaches every page;
   - a monitor is public while an enabled page of its own organization shows it.

   Organizations that are suspended or deleted publish nothing. */

export const statusPagesSchema = z.object({
  pages: z.array(z.object({
    id: z.string().default(() => id()),
    slug: z.string().trim().min(1).max(80).regex(/^[a-z0-9-]+$/, "A status page slug may contain lowercase letters, digits and hyphens."),
    title: z.string().trim().min(1).max(120),
    description: z.string().max(500).default(""),
    logoUrl: z.string().max(1000).default(""),
    tags: z.array(z.string().min(1).max(40)),
    hideHostnames: z.boolean(),
    enabled: z.boolean()
  })).default([])
});

export type PublishedPage = { tenantId: string; page: StatusPageConfig };

const noPages: StatusPageSettings = { pages: [] };
const publishingStatuses = new Set<Tenant["status"]>(["active", "trialing"]);

const covers = (page: StatusPageConfig, monitor: Pick<Monitor, "tags">) => page.tags.every((tag) => monitor.tags.includes(tag));

const sameLabels = (left: string[], right: string[]) => {
  const a = new Set(left);
  const b = new Set(right);
  return a.size === b.size && [...a].every((tag) => b.has(tag));
};

// The default organization first, then by age: the order in which an address
// that several organizations could claim is handed out.
const claimOrder = (left: Tenant, right: Tenant) => {
  if (left.id !== right.id && left.id === DEFAULT_TENANT_ID) return -1;
  if (left.id !== right.id && right.id === DEFAULT_TENANT_ID) return 1;
  return left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id);
};

const pagesByTenant = () => new Map(appSettings.everyTenant("statusPages", noPages).map((entry) => [entry.tenantId, entry.value.pages ?? []]));

/** Enabled pages of every organization that may publish, in claim order. */
const publishedPages = (): PublishedPage[] => {
  const pages = pagesByTenant();
  return tenants.list()
    .filter((tenant) => publishingStatuses.has(tenant.status))
    .sort(claimOrder)
    .flatMap((tenant) => (pages.get(tenant.id) ?? []).filter((page) => page.enabled).map((page) => ({ tenantId: tenant.id, page })));
};

const decode = (value: string) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

/** Labels of an address such as "prod+mail" or "prod,mail". */
export const parseLabels = (value: string) => value.split(/[,+]/).map((tag) => decode(tag).trim()).filter(Boolean);

/** The published page behind a public address, or null when nothing is published there. */
export const findPublishedPage = (address: string): PublishedPage | null => {
  const pages = publishedPages();
  const bySlug = pages.find((entry) => entry.page.slug === address);
  if (bySlug) return bySlug;
  const labels = parseLabels(address);
  if (!labels.length) return null;
  return pages.find((entry) => entry.page.tags.length > 0 && sameLabels(entry.page.tags, labels)) ?? null;
};

/** The monitors a published page shows. */
export const pageMonitors = ({ tenantId, page }: PublishedPage) => monitors.list(tenantId).filter((monitor) => covers(page, monitor));

/** True while an enabled status page of the monitor's own organization shows it. */
export const isPublished = (monitor: Pick<Monitor, "tenantId" | "tags">) => {
  const tenant = tenants.get(monitor.tenantId);
  if (!tenant || !publishingStatuses.has(tenant.status)) return false;
  return appSettings.statusPages(monitor.tenantId).pages.some((page) => page.enabled && covers(page, monitor));
};

/** Public address of the page a subscription was made on. */
export const subscriptionPagePath = (subscription: Pick<StatusSubscription, "pageSlug" | "tags">) =>
  `/public/status/${encodeURIComponent(subscription.pageSlug ?? subscription.tags.join("+"))}.html`;

/**
 * Why these pages cannot be saved for the organization, or null. A slug is a
 * public address, so it may appear only once, here and in every other
 * organization, including on disabled pages that may be enabled again.
 */
export const statusPageConflict = (tenantId: string, pages: Array<Pick<StatusPageConfig, "slug" | "title">>): string | null => {
  const seen = new Set<string>();
  for (const page of pages) {
    if (seen.has(page.slug)) return `Two status pages use the slug "${page.slug}". Give each page its own slug.`;
    seen.add(page.slug);
  }
  const stored = pagesByTenant();
  const taken = new Set(tenants.list()
    .filter((tenant) => tenant.id !== tenantId)
    .flatMap((tenant) => (stored.get(tenant.id) ?? []).map((page) => page.slug)));
  const clash = pages.find((page) => taken.has(page.slug));
  return clash ? `The address /public/status/${clash.slug} already belongs to another organization. Choose a different slug for the page "${clash.title}".` : null;
};

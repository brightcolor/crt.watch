import { Router, type Request } from "express";
import { incidents, monitors, results, subscriptions } from "../storage/repositories.js";
import { sendStatusSubscriptionOptIn } from "../notifications/service.js";
import { NotificationTargetError } from "../notifications/delivery.js";
import { findPublishedPage, isPublished, pageMonitors, parseLabels, subscriptionPagePath, type PublishedPage } from "../status/publication.js";
import { publicIncident, publicMonitor, renderPublicStatusPage, renderStatusPageNotFound, statusPageNotFoundMessage } from "./publicStatusPage.js";
import { badgeLabelFromQuery, renderStatusBadge } from "./publicBadge.js";
import type { MonitorStatus } from "../types.js";

/* Everything here is public. What it shows comes only from status pages an
   organization has published; see status/publication.ts. An address without a
   published page answers 404, and a badge for a monitor that no page shows
   reads "unknown", the same as a badge for a monitor that does not exist. */

export const publicRoutes = Router();

publicRoutes.get("/status/:address.html", (req, res) => {
  const published = findPublishedPage(req.params.address);
  if (!published) return res.status(404).type("html").send(renderStatusPageNotFound());
  res.type("html").send(renderPublicStatusPage(publicStatus(published), {
    subscriptionState: subscriptionState(req.query.subscription),
    subscribePath: `/public/status/${encodeURIComponent(req.params.address)}/subscribe`
  }));
});

publicRoutes.get("/badge/:id.svg", (req, res) => {
  const found = monitors.get(req.params.id);
  const monitor = found && isPublished(found) ? found : null;
  const result = monitor ? results.list(monitor.id, 1)[0] : null;
  const status = monitor?.lastStatus ?? "UNKNOWN";
  const label = badgeLabelFromQuery(req.query, monitor?.name ?? monitor?.host ?? "monitor");
  const value = result?.daysRemaining !== null && result?.daysRemaining !== undefined ? `${status} ${result.daysRemaining}d` : status;
  res.set("Cache-Control", "no-cache").type("image/svg+xml").send(renderStatusBadge({ label, value, status }));
});

publicRoutes.get("/badge/tags/:address.svg", (req, res) => {
  const published = findPublishedPage(req.params.address);
  const status = published ? publicStatus(published) : null;
  const label = badgeLabelFromQuery(req.query, status?.label ?? (parseLabels(req.params.address).join(" + ") || "status"));
  const rollupStatus: MonitorStatus = status?.rollupStatus ?? "UNKNOWN";
  res.set("Cache-Control", "no-cache").type("image/svg+xml").send(renderStatusBadge({ label, value: rollupStatus.toLowerCase(), status: rollupStatus }));
});

publicRoutes.get("/status/:address", (req, res) => {
  const published = findPublishedPage(req.params.address);
  if (!published) return res.status(404).json({ error: statusPageNotFoundMessage });
  res.json(publicStatus(published));
});

publicRoutes.post("/status/:address/subscribe", async (req, res) => {
  const published = findPublishedPage(req.params.address);
  const fromForm = wantsPage(req);
  if (!published) return fromForm ? res.status(404).type("html").send(renderStatusPageNotFound()) : res.status(404).json({ error: statusPageNotFoundMessage });
  const type = req.body?.type === "webhook" ? "webhook" : "email";
  const target = String(req.body?.target ?? "").trim();
  if (!target || target.length > 2000) return res.status(400).json({ error: "Enter an email address or a webhook URL with at most 2000 characters." });
  const subscription = subscriptions.create({ tenantId: published.tenantId, pageSlug: published.page.slug, tags: published.page.tags, type, target, enabled: false });
  const back = `/public/status/${encodeURIComponent(req.params.address)}.html`;
  try {
    await sendStatusSubscriptionOptIn(subscription);
    if (fromForm) return res.redirect(303, `${back}?subscription=pending`);
    return res.status(202).json({ ...publicSubscription(subscription), optInRequired: true });
  } catch (error) {
    subscriptions.delete(subscription.id, subscription.tenantId);
    if (fromForm) return res.redirect(303, `${back}?subscription=failed`);
    const message = error instanceof Error ? error.message : "The opt-in message could not be sent. Check the target and try again.";
    return res.status(error instanceof NotificationTargetError ? 400 : 502).json({ error: message });
  }
});

publicRoutes.get("/subscriptions/:id/confirm", (req, res) => {
  const subscription = subscriptions.confirm(req.params.id);
  if (!subscription) return res.status(404).type("text").send("This subscription does not exist any more. Subscribe again on the status page.");
  res.redirect(303, `${subscriptionPagePath(subscription)}?subscription=confirmed`);
});

const publicStatus = (published: PublishedPage) => {
  const { page } = published;
  const latest = results.latestByMonitor(published.tenantId);
  const selected = pageMonitors(published);
  const counts = selected.reduce<Record<string, number>>((acc, monitor) => {
    acc[monitor.lastStatus] = (acc[monitor.lastStatus] ?? 0) + 1;
    return acc;
  }, {});
  const timeline = selected
    .flatMap((monitor) => incidents.listForMonitor(monitor.id, 10))
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
    .slice(0, 25)
    .map(publicIncident);
  const labelText = page.tags.length ? page.tags.join(" + ") : "all";
  return {
    tag: page.tags[0] ?? "all",
    tags: page.tags,
    label: page.title || labelText,
    title: page.title || `crt.watch status: ${labelText}`,
    description: page.description ?? "",
    logoUrl: page.logoUrl ?? "",
    hideHostnames: page.hideHostnames ?? false,
    rollupStatus: rollup(counts),
    counts,
    summary: `${counts.OK ?? 0} OK, ${counts.WARNING ?? 0} warning, ${(counts.CRITICAL ?? 0) + (counts.DOWN ?? 0)} critical/down`,
    monitors: selected.map((monitor) => publicMonitor(monitor, latest[monitor.id], page)),
    incidents: timeline
  };
};

// The subscriber learns what they subscribed to; the organization id stays internal.
const publicSubscription = (subscription: { id: string; tags: string[]; type: string; target: string; enabled: boolean; createdAt: string }) => ({
  id: subscription.id,
  tags: subscription.tags,
  type: subscription.type,
  target: subscription.target,
  enabled: subscription.enabled,
  createdAt: subscription.createdAt
});

const wantsPage = (req: Request) => Boolean(req.accepts("html")) && !req.is("application/json");
const rollup = (counts: Record<string, number>): MonitorStatus => (counts.DOWN || counts.CRITICAL ? "CRITICAL" : counts.WARNING ? "WARNING" : counts.PAUSED ? "PAUSED" : counts.UNKNOWN ? "UNKNOWN" : "OK");
const subscriptionState = (value: unknown) => value === "pending" || value === "confirmed" || value === "failed" ? value : undefined;

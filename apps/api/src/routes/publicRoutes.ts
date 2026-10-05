import { Router } from "express";
import { appSettings, incidents, monitors, results, subscriptions } from "../storage/repositories.js";
import { sendStatusSubscriptionOptIn } from "../notifications/service.js";
import { NotificationTargetError } from "../notifications/delivery.js";
import { renderPublicStatusPage } from "./publicStatusPage.js";
import { badgeLabelFromQuery, renderStatusBadge } from "./publicBadge.js";
import type { MonitorStatus } from "../types.js";

export const publicRoutes = Router();

publicRoutes.get("/status/:tags.html", (req, res) => {
  const status = publicStatus(req.params.tags);
  res.type("html").send(renderPublicStatusPage(status, {
    subscriptionState: subscriptionState(req.query.subscription),
    subscribePath: `/public/status/${encodeURIComponent(rawTags(req.params.tags))}/subscribe`
  }));
});

publicRoutes.get("/badge/:id.svg", (req, res) => {
  const monitor = monitors.get(req.params.id);
  const result = monitor ? results.list(monitor.id, 1)[0] : null;
  const status = monitor?.lastStatus ?? "UNKNOWN";
  const label = badgeLabelFromQuery(req.query, monitor?.name ?? monitor?.host ?? "monitor");
  const value = result?.daysRemaining !== null && result?.daysRemaining !== undefined ? `${status} ${result.daysRemaining}d` : status;
  res.set("Cache-Control", "no-cache").type("image/svg+xml").send(renderStatusBadge({ label, value, status }));
});

publicRoutes.get("/badge/tags/:tags.svg", (req, res) => {
  const status = publicStatus(req.params.tags);
  const label = badgeLabelFromQuery(req.query, status.label);
  const value = status.rollupStatus.toLowerCase();
  res.set("Cache-Control", "no-cache").type("image/svg+xml").send(renderStatusBadge({ label, value, status: status.rollupStatus }));
});

publicRoutes.get("/status/:tags", (req, res) => res.json(publicStatus(req.params.tags)));
publicRoutes.post("/status/:tags/subscribe", async (req, res) => {
  const page = appSettings.statusPages().pages.find((item) => item.enabled && item.slug === req.params.tags);
  const tags = page?.tags ?? parseTags(req.params.tags);
  const type = req.body?.type === "webhook" ? "webhook" : "email";
  const target = String(req.body?.target ?? "").trim();
  if (!target || target.length > 2000) return res.status(400).json({ error: "Enter an email address or a webhook URL with at most 2000 characters." });
  const subscription = subscriptions.create(tags, type, target, false);
  try {
    await sendStatusSubscriptionOptIn(subscription);
    if (req.accepts("html") && !req.is("application/json")) return res.redirect(303, `/public/status/${encodeURIComponent(rawTags(req.params.tags))}.html?subscription=pending`);
    return res.status(202).json({ ...subscription, optInRequired: true });
  } catch (error) {
    subscriptions.delete(subscription.id);
    if (req.accepts("html") && !req.is("application/json")) return res.redirect(303, `/public/status/${encodeURIComponent(rawTags(req.params.tags))}.html?subscription=failed`);
    const message = error instanceof Error ? error.message : "The opt-in message could not be sent. Check the target and try again.";
    return res.status(error instanceof NotificationTargetError ? 400 : 502).json({ error: message });
  }
});

publicRoutes.get("/subscriptions/:id/confirm", (req, res) => {
  const subscription = subscriptions.confirm(req.params.id);
  if (!subscription) return res.status(404).type("text").send("Subscription not found.");
  res.redirect(303, `/public/status/${encodeURIComponent(subscription.tags.join("+"))}.html?subscription=confirmed`);
});

const publicStatus = (rawTags: string) => {
  const page = appSettings.statusPages().pages.find((item) => item.enabled && item.slug === rawTags);
  const tags = page?.tags ?? parseTags(rawTags);
  const latest = results.latestByMonitor();
  const selected = monitors.list().filter((monitor) => tags.length ? tags.every((tag) => monitor.tags.includes(tag)) : true);
  const counts = selected.reduce<Record<string, number>>((acc, monitor) => {
    acc[monitor.lastStatus] = (acc[monitor.lastStatus] ?? 0) + 1;
    return acc;
  }, {});
  const rollupStatus = rollup(counts);
  const timeline = selected
    .flatMap((monitor) => incidents.listForMonitor(monitor.id, 10))
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
    .slice(0, 25);
  return {
    tag: tags[0] ?? "all",
    tags,
    label: page?.title ?? (tags.length ? tags.join(" + ") : "all"),
    title: page?.title ?? `crt.watch status: ${tags.length ? tags.join(" + ") : "all"}`,
    description: page?.description ?? "",
    logoUrl: page?.logoUrl ?? "",
    hideHostnames: page?.hideHostnames ?? false,
    rollupStatus,
    counts,
    summary: `${counts.OK ?? 0} OK, ${counts.WARNING ?? 0} warning, ${(counts.CRITICAL ?? 0) + (counts.DOWN ?? 0)} critical/down`,
    monitors: selected.map((monitor) => ({
      id: monitor.id,
      name: monitor.name,
      host: monitor.host,
      port: monitor.port,
      status: monitor.lastStatus,
      checkedAt: latest[monitor.id]?.checkedAt ?? null,
      daysRemaining: latest[monitor.id]?.daysRemaining ?? null,
      message: latest[monitor.id]?.message ?? "No check result yet."
    })),
    incidents: timeline
  };
};

const parseTags = (value: string) => value.split(/[,+]/).map((tag) => decodeURIComponent(tag).trim()).filter(Boolean);
const rawTags = (value: string) => value;
const rollup = (counts: Record<string, number>): MonitorStatus => (counts.DOWN || counts.CRITICAL ? "CRITICAL" : counts.WARNING ? "WARNING" : counts.PAUSED ? "PAUSED" : counts.UNKNOWN ? "UNKNOWN" : "OK");
const subscriptionState = (value: unknown) => value === "pending" || value === "confirmed" || value === "failed" ? value : undefined;

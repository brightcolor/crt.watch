import { createHash, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { resolveTenant } from "../auth/auth.js";
import { bearerToken } from "../auth/tokens.js";
import { env } from "../config/env.js";
import { monitors, results, tenants } from "../storage/repositories.js";
import type { Monitor } from "../types.js";

/* Prometheus metrics.

   With METRICS_ACCESS=authenticated (the default) the endpoint answers only
   to a caller that proves who it is:

   - the bearer token from METRICS_TOKEN, meant for the operator's Prometheus,
     sees the monitors of every organization;
   - a signed-in session or a crt.watch API token sees the monitors of the
     organization selected for the request, as everywhere else in the API.

   METRICS_ACCESS=public answers everyone with every organization's monitors,
   for an instance that only a trusted network can reach. Each series carries
   the organization's slug as a label. */

export type MetricsSettings = { access: "authenticated" | "public"; token: string };

type MetricsScope = { kind: "platform" } | { kind: "organization"; tenantId: string };

const statusValue: Record<string, number> = { OK: 1, WARNING: 0.5, CRITICAL: 0, DOWN: 0, PAUSED: -1, UNKNOWN: -1 };

export const metricsAuthorizationMessage = "/metrics needs authorization. Send \"Authorization: Bearer <token>\" with the METRICS_TOKEN of this crt.watch instance or with a crt.watch API token, or sign in first. The operator sets METRICS_TOKEN in the environment.";

const digest = (value: string) => createHash("sha256").update(value).digest();
const sameSecret = (presented: string, expected: string) => timingSafeEqual(digest(presented), digest(expected));

const scopeOf = (res: Response): MetricsScope | undefined => res.locals.metricsScope as MetricsScope | undefined;

/** Decides who may read the metrics and which organizations they cover. */
export const metricsAccess = (settings: MetricsSettings = { access: env.metricsAccess, token: env.metricsToken }) =>
  (req: Request, res: Response, next: NextFunction) => {
    if (settings.access === "public") {
      res.locals.metricsScope = { kind: "platform" } satisfies MetricsScope;
      return next();
    }
    const presented = bearerToken(req.get("authorization"));
    if (settings.token && presented && sameSecret(presented, settings.token)) {
      res.locals.metricsScope = { kind: "platform" } satisfies MetricsScope;
      return next();
    }
    if (!req.user) {
      return res.status(401).set("WWW-Authenticate", "Bearer realm=\"crt.watch metrics\"").type("text/plain").send(metricsAuthorizationMessage);
    }
    return resolveTenant(req, res, () => {
      res.locals.metricsScope = { kind: "organization", tenantId: req.currentTenant!.id } satisfies MetricsScope;
      next();
    });
  };

// Answers only behind metricsAccess; without a decided scope it shows nothing.
export const metricsHandler = (_req: Request, res: Response) => {
  const scope = scopeOf(res);
  if (!scope) return res.status(401).type("text/plain").send(metricsAuthorizationMessage);
  const slugs = new Map(tenants.list().map((tenant) => [tenant.id, tenant.slug]));
  const covered: Monitor[] = scope.kind === "platform" ? monitors.listAll() : monitors.list(scope.tenantId);
  const latest = results.latestByMonitor(scope.kind === "platform" ? undefined : scope.tenantId);
  const lines = [
    "# HELP crtwatch_monitor_status Monitor status as numeric value.",
    "# TYPE crtwatch_monitor_status gauge",
    "# HELP crtwatch_cert_days_remaining Certificate days remaining.",
    "# TYPE crtwatch_cert_days_remaining gauge",
    "# HELP crtwatch_last_check_timestamp Last check timestamp as Unix seconds.",
    "# TYPE crtwatch_last_check_timestamp gauge",
    "# HELP crtwatch_check_duration_seconds Last check duration in seconds.",
    "# TYPE crtwatch_check_duration_seconds gauge"
  ];

  for (const monitor of covered) {
    const labels = prometheusLabels({ organization: slugs.get(monitor.tenantId) ?? monitor.tenantId, monitor_id: monitor.id, monitor_name: monitor.name, host: monitor.host, type: monitor.type, tags: monitor.tags.join(",") });
    const result = latest[monitor.id];
    lines.push(`crtwatch_monitor_status{${labels}} ${statusValue[monitor.lastStatus] ?? -1}`);
    if (result?.daysRemaining !== null && result?.daysRemaining !== undefined) lines.push(`crtwatch_cert_days_remaining{${labels}} ${result.daysRemaining}`);
    if (result?.checkedAt) lines.push(`crtwatch_last_check_timestamp{${labels}} ${Math.floor(new Date(result.checkedAt).getTime() / 1000)}`);
    if (result?.durationMs !== undefined) lines.push(`crtwatch_check_duration_seconds{${labels}} ${result.durationMs / 1000}`);
  }

  res.type("text/plain; version=0.0.4").send(`${lines.join("\n")}\n`);
};

const prometheusLabels = (labels: Record<string, string>) =>
  Object.entries(labels).map(([key, value]) => `${key}="${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`).join(",");

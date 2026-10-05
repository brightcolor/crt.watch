import { env } from "../config/env.js";
import type { CheckResult, Monitor, NotificationChannel, NotificationRoute, Severity, SmtpSettings, StatusSubscription, UserAlertSettings } from "../types.js";
import { alerts, appSettings, deliveries, results as checkResults, userAlerts } from "../storage/repositories.js";
import { alertFingerprint } from "../checks/status.js";
import { isInMaintenance } from "../checks/maintenance.js";
import { isPublished, subscriptionPagePath } from "../status/publication.js";
import { mailTransport, postNotification, type DeliveryRequest } from "./delivery.js";

export const dispatchAlerts = async (monitor: Monitor, result: CheckResult, configured: NotificationChannel[]) => {
  const settings = appSettings.alerting(monitor.tenantId);
  if (isInMaintenance(monitor, appSettings.maintenance(monitor.tenantId))) return;
  if (result.severity === "info" && result.status === "OK") {
    if (settings.recoveryEnabled && monitor.lastStatus !== "OK" && monitor.lastStatus !== "UNKNOWN") {
      await sendToChannels(monitor, { ...result, severity: "recovery", message: "Monitor recovered." }, configured);
    }
    return;
  }
  if (isQuietHour(settings.quietStart, settings.quietEnd) && settings.quietHoursEnabled && (settings.quietSuppressCritical || result.severity !== "critical")) {
    return;
  }
  if (isWithinGracePeriod(monitor, result)) return;
  const fingerprint = alertFingerprint(result);
  if (!alerts.shouldSend(monitor.id, result.status, fingerprint, settings.resendAfterHours)) return;
  await sendToChannels(monitor, result, configured);
};

// The sample monitor belongs to the channel's organization, so an email test uses that organization's SMTP settings.
export const testChannel = async (channel: NotificationChannel) => {
  await sendChannel(channel, { id: "test", tenantId: channel.tenantId, name: "Test Monitor", host: "example.com", port: 443 } as Monitor, sampleResult());
};

/* Subscribers hear about monitors of the organization whose page they
   subscribed to, and only while a published status page of that organization
   shows the monitor. */
export const dispatchStatusSubscriptions = async (monitor: Monitor, result: CheckResult, event: "opened" | "resolved", configured: StatusSubscription[]) => {
  if (isInMaintenance(monitor, appSettings.maintenance(monitor.tenantId))) return;
  if (!isPublished(monitor)) return;
  const targets = configured.filter((subscription) => subscription.enabled && subscription.tenantId === monitor.tenantId && subscription.tags.every((tag) => monitor.tags.includes(tag)));
  await Promise.allSettled(targets.map((subscription) => sendStatusSubscription(subscription, monitor, result, event)));
};

export const sendStatusSubscriptionOptIn = async (subscription: StatusSubscription) => {
  const confirmUrl = `${env.baseUrl}/public/subscriptions/${encodeURIComponent(subscription.id)}/confirm`;
  const statusPage = `${env.baseUrl}${subscriptionPagePath(subscription)}`;
  if (subscription.type === "webhook") {
    return postJson(subscription.target, {
      event: "subscription_opt_in",
      message: "Confirm this crt.watch status page subscription before incident updates are sent.",
      confirm_url: confirmUrl,
      status_page: statusPage,
      tags: subscription.tags
    });
  }
  // The same SMTP settings that will carry the incident updates later.
  const smtp = appSettings.smtp(subscription.tenantId);
  await mailTransport(smtp).sendMail({
    from: smtp.from || "crt.watch@localhost",
    to: subscription.target,
    subject: "[crt.watch Status] Confirm your subscription",
    text: `Confirm your crt.watch status page subscription before incident updates are sent.

Status page: ${statusPage}
Confirm subscription: ${confirmUrl}

If you did not request this subscription, ignore this message.
`
  });
};

export const buildPayload = (monitor: Monitor, result: CheckResult) => ({
  monitor_id: monitor.id,
  monitor_name: monitor.name,
  host: monitor.host,
  port: monitor.port,
  status: result.status.toLowerCase(),
  severity: result.severity,
  message: result.message,
  days_remaining: result.daysRemaining,
  valid_from: result.validFrom,
  valid_until: result.validUntil,
  issuer: result.issuer,
  fingerprint_sha256: result.fingerprintSha256,
  tls_grade: result.tlsGrade,
  tls_score: result.tlsScore,
  tls_supported_versions: result.tlsSupportedVersions ?? [],
  ssl_labs_grade: result.sslLabsGrade,
  ssl_labs_status: result.sslLabsStatus,
  ssl_labs_url: result.sslLabsUrl,
  ssl_labs_findings: result.sslLabsFindings ?? [],
  resolved_addresses: result.dns?.addresses ?? [],
  dns_mismatches: result.dns?.mismatches ?? [],
  checked_at: result.checkedAt,
  url: `${env.baseUrl}/monitors/${monitor.id}`
});

const sendStatusSubscription = async (subscription: StatusSubscription, monitor: Monitor, result: CheckResult, event: "opened" | "resolved") => {
  const payload = {
    ...buildPayload(monitor, result),
    event,
    status_page: `${env.baseUrl}${subscriptionPagePath(subscription)}`
  };
  if (subscription.type === "webhook") return postJson(subscription.target, payload);
  const smtp = appSettings.smtp(monitor.tenantId);
  await mailTransport(smtp).sendMail({
    from: smtp.from || "crt.watch@localhost",
    to: subscription.target,
    subject: `[crt.watch Status] ${event === "resolved" ? "Resolved" : "Incident"}: ${monitor.name}`,
    text: `${monitor.name}: ${result.message}\n\nStatus: ${result.status}\nChecked at: ${result.checkedAt}\nStatus page: ${payload.status_page}\n`
  });
};

const sendToChannels = async (monitor: Monitor, result: CheckResult, configured: NotificationChannel[]) => {
  const selected = selectedAlertTargets(monitor, result, appSettings.notificationRoutes(monitor.tenantId), userAlerts.list(monitor.tenantId), configured.map((channel) => channel.id));
  const targets = selected.flatMap((target) => {
    const channel = configured.find((item) => item.id === target.channelId);
    return channel?.enabled ? [{ channel, recipient: target.recipient }] : [];
  });
  await Promise.allSettled(targets.map(async ({ channel, recipient }) => {
    try {
      await sendChannel(channel, monitor, result, recipient);
      deliveries.record(deliveryBase(channel, monitor, result, recipient, "sent"));
      alerts.record(monitor.id, channel.id, result.severity, result.status, alertFingerprint(result), result.message);
    } catch (error) {
      deliveries.record(deliveryBase(channel, monitor, result, recipient, "failed", error instanceof Error ? error.message : String(error)));
      throw error;
    }
  }));
};

const deliveryBase = (channel: NotificationChannel, monitor: Monitor, result: CheckResult, target: string, deliveryStatus: "sent" | "failed", error?: string) => ({
  monitorId: monitor.id,
  channelId: channel.id,
  channelName: channel.name,
  provider: channel.type,
  target: target || String(channel.config.url ?? channel.config.to ?? channel.config.topic ?? ""),
  severity: result.severity,
  status: result.status,
  deliveryStatus,
  message: result.message,
  error: error ?? null
});

const isWithinGracePeriod = (monitor: Monitor, result: CheckResult) => {
  if (result.status === "OK" || monitor.gracePeriodSeconds <= 0) return false;
  const failureStartedAt = checkResults.consecutiveFailureStartedAt(monitor.id);
  if (!failureStartedAt) return false;
  return Date.now() - new Date(failureStartedAt).getTime() < monitor.gracePeriodSeconds * 1000;
};

const selectedAlertTargets = (monitor: Monitor, result: CheckResult, routes: NotificationRoute[], personal: UserAlertSettings[], fallback: string[]) => {
  const explicit = new Map<string, string>();
  for (const channelId of monitor.notificationChannelIds) explicit.set(channelId, monitor.notificationRecipients[channelId] ?? "");
  for (const route of routes) {
    if (!route.enabled) continue;
    const tagMatch = !route.tags.length || route.tags.some((tag) => monitor.tags.includes(tag));
    const severityMatch = !route.severities.length || route.severities.includes(result.severity);
    const delayed = (route.delayMinutes ?? 0) > 0 && result.status !== "OK" && !delayElapsed(monitor.id, route.delayMinutes ?? 0);
    if (delayed) continue;
    if (tagMatch && severityMatch) route.channelIds.forEach((channelId) => explicit.set(channelId, route.recipients[channelId] ?? explicit.get(channelId) ?? ""));
  }
  if (!explicit.size) fallback.forEach((channelId) => explicit.set(channelId, ""));
  const targets = [...explicit.entries()].map(([channelId, recipient]) => ({ channelId, recipient }));
  if (result.severity !== "critical") {
    for (const setting of personal) {
      if (!setting.enabled || !setting.severities.includes(result.severity as any)) continue;
      const tagMatch = !setting.tags.length || setting.tags.some((tag) => monitor.tags.includes(tag));
      if (!tagMatch) continue;
      setting.channelIds.forEach((channelId) => targets.push({ channelId, recipient: setting.recipients[channelId] ?? "" }));
    }
  }
  return dedupeTargets(targets);
};

const dedupeTargets = (targets: Array<{ channelId: string; recipient: string }>) => {
  const seen = new Set<string>();
  return targets.filter((target) => {
    const key = `${target.channelId}:${target.recipient}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

const delayElapsed = (monitorId: string, delayMinutes: number) => {
  const failureStartedAt = checkResults.consecutiveFailureStartedAt(monitorId);
  if (!failureStartedAt) return false;
  return Date.now() - new Date(failureStartedAt).getTime() >= delayMinutes * 60_000;
};

const sendChannel = async (channel: NotificationChannel, monitor: Monitor, result: CheckResult, recipient = "") => {
  if (channel.type === "email") return sendEmail(channel, monitor, result, recipient);
  if (channel.type === "pushover") return postForm(endpoint(channel, ["https://api", "pushover", "net/1/messages.json"]), {
    token: String(channel.config.apiToken ?? ""),
    user: recipient || String(channel.config.userKey ?? ""),
    message: result.message,
    title: `[crt.watch] ${monitor.name}`,
    priority: String(priorityFor(result.severity))
  });
  if (channel.type === "telegram") {
    const url = endpoint(channel, ["https://api", "telegram", `org/bot${String(channel.config.botToken ?? "")}/sendMessage`]);
    return postJson(url, { chat_id: recipient || channel.config.chatId, text: result.message });
  }
  if (channel.type === "matrix") return postJson(matrixEndpoint(channel, recipient), { msgtype: "m.text", body: result.message });
  if (channel.type === "pagerduty") return postJson(endpoint(channel, ["https://events", "pagerduty", "com/v2/enqueue"]), pagerDutyPayload(channel, monitor, result));
  if (channel.type === "opsgenie") return postJson(endpoint(channel, ["https://api", "opsgenie", "com/v2/alerts"]), opsgeniePayload(monitor, result), { Authorization: `GenieKey ${String(channel.config.apiKey ?? "")}` });
  return postJson(recipient || endpoint(channel), providerPayload(channel, monitor, result));
};

const endpoint = (channel: NotificationChannel, fallbackParts?: string[]) => {
  const url = String(channel.config.url ?? "");
  if (url) return url;
  if (fallbackParts) return fallbackParts.join(".");
  throw new Error(`Notification channel${channel.name ? ` "${channel.name}"` : ""} has no URL. Enter the endpoint URL in the channel settings.`);
};

const sendEmail = async (channel: NotificationChannel, monitor: Monitor, result: CheckResult, recipient = "") => {
  const globalSmtp = appSettings.smtp(monitor.tenantId);
  const smtp = mergeSmtp(globalSmtp, channel.config);
  // The SMTP host of the channel or the organization passes the same address check as webhooks.
  await mailTransport(smtp).sendMail({
    from: String(channel.config.from ?? smtp.from ?? "crt.watch@localhost"),
    to: recipient || String(channel.config.to ?? channel.config.username ?? ""),
    subject: `[crt.watch] ${subjectFor(result.severity)}: ${monitor.name}`,
    text: emailBody(monitor, result)
  });
};

const emailBody = (monitor: Monitor, result: CheckResult) => `The certificate check for ${monitor.name} needs attention.

Host: ${monitor.host}
Port: ${monitor.port}
Issuer: ${result.issuer ?? "unknown"}
Valid until: ${result.validUntil ?? "unknown"}
Days remaining: ${result.daysRemaining ?? "unknown"}
Status: ${result.status}

Problem:
${result.problems.join("\n") || result.message}

Recommendation:
Renew the certificate if it is close to expiry and verify the complete certificate chain afterwards.

crt.watch URL: ${env.baseUrl}/monitors/${monitor.id}
`;

const sampleResult = (): CheckResult => ({
  id: "test-result",
  monitorId: "test",
  status: "WARNING",
  severity: "warning",
  message: "crt.watch test notification.",
  checkedAt: new Date().toISOString(),
  durationMs: 0,
  daysRemaining: 30,
  validFrom: null,
  validUntil: new Date(Date.now() + 30 * 86_400_000).toISOString(),
  commonName: "example.com",
  subjectAltNames: ["example.com"],
  issuer: "crt.watch",
  serialNumber: null,
  fingerprintSha256: "test",
  tlsVersion: "TLSv1.3",
  cipherSuite: null,
  tlsSupportedVersions: ["TLSv1.2", "TLSv1.3"],
  chain: [],
  problems: [],
  rawError: null
});

const postJson = (url: string, payload: unknown, headers: Record<string, string> = {}) =>
  deliver({ url, headers, body: JSON.stringify(payload), contentType: "application/json" });

const postForm = (url: string, values: Record<string, string>) =>
  deliver({ url, body: new URLSearchParams(values).toString(), contentType: "application/x-www-form-urlencoded;charset=UTF-8" });

// postNotification refuses targets outside the operator's network policy; see delivery.ts.
const deliver = async (request: DeliveryRequest) => {
  const { status, host } = await postNotification(request);
  if (status < 200 || status > 299) throw new Error(`Notification endpoint ${host} answered with HTTP ${status}. Check the URL and the credentials of this channel.`);
};

const mergeSmtp = (globalSmtp: SmtpSettings, config: Record<string, unknown>): SmtpSettings => ({
  host: String(config.host || globalSmtp.host),
  port: Number(config.port || globalSmtp.port || 587),
  username: String(config.username || globalSmtp.username || ""),
  password: String(config.password || globalSmtp.password || ""),
  from: String(config.from || globalSmtp.from || ""),
  secure: Boolean(config.secure ?? globalSmtp.secure),
  starttls: Boolean(config.starttls ?? globalSmtp.starttls)
});

const providerPayload = (channel: NotificationChannel, monitor: Monitor, result: CheckResult) => {
  const payload = buildPayload(monitor, result);
  if (channel.type === "discord") return { content: `**${monitor.name}**: ${result.message}`, embeds: [{ title: monitor.name, description: result.problems.join("\n") || result.message, color: result.severity === "critical" ? 15_585_873 : 13_801_762 }] };
  if (channel.type === "slack" || channel.type === "mattermost") return { text: `*${monitor.name}* ${result.status}: ${result.message}`, attachments: [{ color: result.severity === "critical" ? "danger" : "warning", text: result.problems.join("\n") }] };
  if (channel.type === "teams") return { title: `crt.watch ${result.status}`, text: `${monitor.name}: ${result.message}` };
  if (channel.type === "ntfy") return { topic: channel.config.topic, title: `crt.watch ${result.status}`, message: `${monitor.name}: ${result.message}`, priority: result.severity === "critical" ? 5 : 3, tags: ["warning"] };
  if (channel.type === "gotify") return { title: `crt.watch ${result.status}`, message: `${monitor.name}: ${result.message}`, priority: result.severity === "critical" ? 8 : 4 };
  return payload;
};

const matrixEndpoint = (channel: NotificationChannel, recipient = "") => {
  const baseUrl = String(channel.config.baseUrl ?? "").replace(/\/$/, "");
  const roomId = encodeURIComponent(recipient || String(channel.config.roomId ?? ""));
  const token = encodeURIComponent(String(channel.config.accessToken ?? ""));
  if (!baseUrl || !roomId || !token) return endpoint(channel);
  return `${baseUrl}/_matrix/client/v3/rooms/${roomId}/send/m.room.message?access_token=${token}`;
};

const pagerDutyPayload = (channel: NotificationChannel, monitor: Monitor, result: CheckResult) => ({
  routing_key: String(channel.config.integrationKey ?? ""),
  event_action: result.severity === "recovery" ? "resolve" : "trigger",
  dedup_key: monitor.id,
  payload: {
    summary: `${monitor.name}: ${result.message}`,
    severity: result.severity === "critical" ? "critical" : "warning",
    source: monitor.host,
    custom_details: buildPayload(monitor, result)
  }
});

const opsgeniePayload = (monitor: Monitor, result: CheckResult) => ({
  message: `${monitor.name}: ${result.message}`,
  alias: monitor.id,
  priority: result.severity === "critical" ? "P1" : "P3",
  details: buildPayload(monitor, result)
});

const isQuietHour = (start: string, end: string, date = new Date()) => {
  const now = date.getHours() * 60 + date.getMinutes();
  const startMinutes = parseClock(start);
  const endMinutes = parseClock(end);
  if (startMinutes === endMinutes) return false;
  return startMinutes < endMinutes ? now >= startMinutes && now < endMinutes : now >= startMinutes || now < endMinutes;
};

const parseClock = (value: string) => {
  const [hours, minutes] = value.split(":").map(Number);
  return (Number.isFinite(hours) ? hours : 0) * 60 + (Number.isFinite(minutes) ? minutes : 0);
};

const priorityFor = (severity: Severity) => severity === "critical" ? 1 : severity === "recovery" ? 0 : -1;
const subjectFor = (severity: Severity) => severity === "recovery" ? "Recovered" : severity === "critical" ? "Critical certificate problem" : "Certificate warning";

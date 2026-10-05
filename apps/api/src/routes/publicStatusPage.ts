import type { CheckResult, Incident, Monitor, MonitorStatus, StatusPageConfig } from "../types.js";

/* Host and port are left out when the page hides host names, so the JSON
   address shows what the HTML page shows. */
export type PublicMonitor = {
  id: string;
  name: string;
  host?: string;
  port?: number;
  status: MonitorStatus;
  checkedAt: string | null;
  daysRemaining: number | null;
  message: string;
};

/* What a monitor shows in public: its name, state and latest message, and its
   host and port while the page shows host names. The status page, its JSON and
   the updates to its subscribers are all built from this. */
export const publicMonitor = (
  monitor: Pick<Monitor, "id" | "name" | "host" | "port" | "lastStatus">,
  result: Pick<CheckResult, "checkedAt" | "daysRemaining" | "message"> | undefined,
  page: Pick<StatusPageConfig, "hideHostnames">
): PublicMonitor => ({
  id: monitor.id,
  name: monitor.name,
  ...(page.hideHostnames ? {} : { host: monitor.host, port: monitor.port }),
  status: monitor.lastStatus,
  checkedAt: result?.checkedAt ?? null,
  daysRemaining: result?.daysRemaining ?? null,
  message: result?.message ?? "No check result yet."
});

/* What an incident shows in public: no acknowledgement, assignee or notes,
   which are the organization's internal working state. */
export type PublicIncident = Pick<Incident, "monitorId" | "status" | "severity" | "message" | "startedAt" | "resolvedAt">;

export const publicIncident = (incident: Incident): PublicIncident => ({
  monitorId: incident.monitorId,
  status: incident.status,
  severity: incident.severity,
  message: incident.message,
  startedAt: incident.startedAt,
  resolvedAt: incident.resolvedAt ?? null
});

type PublicStatusView = {
  label: string;
  title: string;
  description: string;
  logoUrl: string;
  hideHostnames: boolean;
  rollupStatus: MonitorStatus;
  counts: Record<string, number>;
  summary: string;
  monitors: PublicMonitor[];
  incidents: PublicIncident[];
};

type RenderOptions = {
  subscriptionState?: "pending" | "confirmed" | "failed";
  subscribePath: string;
};

export const renderPublicStatusPage = (status: PublicStatusView, options: RenderOptions) => {
  const tone = toneFor(status.rollupStatus);
  const counts = status.counts;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex">
  <title>${escapeHtml(status.title)}</title>
  <style>${styles}</style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="brand-line">
        ${status.logoUrl ? `<img class="logo" src="${escapeHtml(status.logoUrl)}" alt="">` : `<span class="mark">SR</span>`}
        <span class="brand-name">crt.watch</span>
      </div>
      <div class="hero-grid">
        <div>
          <p class="eyebrow">Public status</p>
          <h1>${escapeHtml(status.title)}</h1>
          <p class="lead">${escapeHtml(status.description || tone.description)}</p>
        </div>
        <div class="rollup ${tone.className}">
          <span class="pulse"></span>
          <strong>${escapeHtml(tone.headline)}</strong>
          <small>${escapeHtml(status.summary)}</small>
        </div>
      </div>
    </section>

    ${notice(options.subscriptionState)}

    <section class="summary-grid" aria-label="Status summary">
      ${statCard("Operational", counts.OK ?? 0, "OK")}
      ${statCard("Warnings", counts.WARNING ?? 0, "WARNING")}
      ${statCard("Critical or down", (counts.CRITICAL ?? 0) + (counts.DOWN ?? 0), "CRITICAL")}
      ${statCard("Paused or pending", (counts.PAUSED ?? 0) + (counts.UNKNOWN ?? 0), "UNKNOWN")}
    </section>

    <section class="surface">
      <div class="section-head">
        <div>
          <p class="eyebrow">Monitors</p>
          <h2>Current service health</h2>
        </div>
        <span class="muted">${status.monitors.length} monitored target${status.monitors.length === 1 ? "" : "s"}</span>
      </div>
      <div class="monitor-list">
        ${status.monitors.map((monitor) => monitorRow(monitor, status.hideHostnames)).join("") || emptyState("No monitors match this status page yet.")}
      </div>
    </section>

    <section class="surface">
      <div class="section-head">
        <div>
          <p class="eyebrow">Timeline</p>
          <h2>Incident history</h2>
        </div>
        <span class="muted">${status.incidents.length ? "Latest incidents" : "No incidents"}</span>
      </div>
      <div class="timeline">
        ${status.incidents.map(incidentRow).join("") || emptyState("No incidents have been recorded for this page.")}
      </div>
    </section>

    <section class="subscribe surface">
      <div>
        <p class="eyebrow">Subscribe</p>
        <h2>Get incident updates</h2>
        <p class="muted">Double opt-in is required. We send a confirmation link first and alerts only start after confirmation.</p>
      </div>
      <form method="post" action="${escapeHtml(options.subscribePath)}">
        <select name="type" aria-label="Subscription type">
          <option value="email">Email</option>
          <option value="webhook">Webhook</option>
        </select>
        <input name="target" placeholder="email@example.com or webhook URL" required>
        <button>Send opt-in</button>
      </form>
    </section>
  </main>
</body>
</html>`;
};

export const statusPageNotFoundMessage = "No status page is published at this address. Check the link, or ask the organization that shared it whether the page is still published.";

/* The answer for an address that no organization has published. It reads the
   same whether nothing exists there or something exists but is private. */
export const renderStatusPageNotFound = () => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex">
  <title>Status page not found</title>
  <style>${styles}</style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="brand-line"><span class="mark">SR</span><span class="brand-name">crt.watch</span></div>
      <p class="eyebrow">Public status</p>
      <h1>Status page not found</h1>
      <p class="lead">${escapeHtml(statusPageNotFoundMessage)}</p>
    </section>
  </main>
</body>
</html>`;

const statCard = (label: string, value: number, status: MonitorStatus) => {
  const tone = toneFor(status);
  return `<article class="stat ${tone.className}"><span>${escapeHtml(label)}</span><strong>${value}</strong></article>`;
};

const monitorRow = (monitor: PublicMonitor, hideHostnames: boolean) => {
  const tone = toneFor(monitor.status);
  const target = hideHostnames || !monitor.host ? "" : `<span>${escapeHtml(monitor.host)}:${monitor.port ?? ""}</span>`;
  const days = monitor.daysRemaining === null ? "" : `<span>${monitor.daysRemaining} days remaining</span>`;
  return `<article class="monitor">
    <div class="status-badge ${tone.className}"><span class="dot"></span>${escapeHtml(tone.label)}</div>
    <div>
      <h3>${escapeHtml(monitor.name)}</h3>
      <p>${escapeHtml(monitor.message)}</p>
      <div class="meta">${target}${days}<span>Checked ${formatDate(monitor.checkedAt)}</span></div>
    </div>
  </article>`;
};

const incidentRow = (incident: PublicIncident) => {
  const tone = toneFor(incident.status);
  const resolved = incident.resolvedAt ? `Resolved ${formatDate(incident.resolvedAt)}` : "Open";
  return `<article class="incident">
    <span class="rail ${tone.className}"></span>
    <div>
      <div class="incident-title"><strong>${escapeHtml(tone.label)}</strong><span>${escapeHtml(resolved)}</span></div>
      <p>${escapeHtml(incident.message)}</p>
      <small>Started ${formatDate(incident.startedAt)}</small>
    </div>
  </article>`;
};

const notice = (state?: RenderOptions["subscriptionState"]) => {
  if (state === "pending") return `<section class="notice">Confirmation sent. The subscription is inactive until the opt-in link is confirmed.</section>`;
  if (state === "confirmed") return `<section class="notice success">Subscription confirmed. Incident updates are now active.</section>`;
  if (state === "failed") return `<section class="notice error">The opt-in message could not be sent. Check the email address, or for a webhook that the URL starts with https:// or http:// and is reachable from the internet, then try again.</section>`;
  return "";
};

const emptyState = (text: string) => `<div class="empty">${escapeHtml(text)}</div>`;

const toneFor = (status: string) => {
  if (status === "OK") return { className: "ok", label: "Operational", headline: "All systems operational", description: "All monitored checks are currently healthy." };
  if (status === "WARNING") return { className: "warning", label: "Degraded", headline: "Attention recommended", description: "One or more checks need attention soon." };
  if (status === "CRITICAL" || status === "DOWN") return { className: "critical", label: "Incident", headline: "Service incident active", description: "One or more monitored checks are currently failing." };
  if (status === "PAUSED") return { className: "muted-state", label: "Paused", headline: "Monitoring paused", description: "The selected checks are currently paused." };
  return { className: "muted-state", label: "Pending", headline: "Status pending", description: "One or more checks have not reported a result yet." };
};

const formatDate = (value?: string | null) => {
  if (!value) return "not checked yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("de-DE", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short"
  }).format(date);
};

export const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]!));

const styles = `
:root{color-scheme:light;--bg:#f5f7fa;--surface:#fff;--surface-2:#f9fafb;--line:#d8dee8;--text:#18212f;--muted:#667085;--ok:#16823a;--warning:#a16207;--critical:#c42626;--shadow:0 18px 45px rgba(24,33,47,.08)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.page{width:min(1120px,100%);margin:0 auto;padding:42px 24px 56px;display:grid;gap:22px}.hero,.surface,.stat{border:1px solid var(--line);border-radius:16px;background:var(--surface);box-shadow:var(--shadow)}.hero{padding:32px}.brand-line{display:flex;align-items:center;gap:12px;margin-bottom:28px}.mark{display:grid;width:38px;height:38px;place-items:center;border-radius:10px;background:#18212f;color:#fff;font-weight:600}.logo{max-height:48px;max-width:220px}.brand-name{color:var(--muted);font-weight:600}.hero-grid{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:28px;align-items:end}.eyebrow{margin:0 0 8px;color:var(--muted);font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase}h1,h2,h3,p{margin:0}h1{max-width:780px;font-size:clamp(34px,5vw,56px);line-height:1.02}h2{font-size:22px}.lead{max-width:680px;margin-top:14px;color:var(--muted);font-size:17px;line-height:1.6}.rollup{display:grid;gap:8px;border-radius:14px;padding:18px;background:var(--surface-2)}.rollup strong{font-size:22px}.rollup small{color:var(--muted);font-weight:600}.pulse{width:12px;height:12px;border-radius:50%;background:currentColor;box-shadow:0 0 0 7px color-mix(in srgb,currentColor 14%,transparent)}.summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.stat{display:grid;gap:8px;padding:18px}.stat span{color:var(--muted);font-size:13px;font-weight:600}.stat strong{font-size:34px}.surface{display:grid;gap:18px;padding:24px}.section-head{display:flex;align-items:end;justify-content:space-between;gap:18px}.monitor-list,.timeline{display:grid;gap:12px}.monitor,.incident{display:grid;grid-template-columns:150px minmax(0,1fr);gap:18px;align-items:start;border:1px solid var(--line);border-radius:14px;background:var(--surface-2);padding:16px}.monitor h3{font-size:18px}.monitor p,.incident p{margin-top:5px;color:var(--text);line-height:1.45}.meta{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px;color:var(--muted);font-size:13px}.meta span:not(:empty)::before{content:"";display:inline-block;width:5px;height:5px;margin-right:7px;border-radius:50%;background:var(--line);vertical-align:middle}.status-badge{display:inline-flex;width:max-content;align-items:center;gap:8px;border-radius:999px;padding:7px 11px;background:color-mix(in srgb,currentColor 10%,transparent);font-size:13px;font-weight:600}.dot{width:8px;height:8px;border-radius:50%;background:currentColor}.ok{color:var(--ok)}.warning{color:var(--warning)}.critical{color:var(--critical)}.muted-state{color:var(--muted)}.incident{grid-template-columns:6px minmax(0,1fr)}.rail{width:6px;height:100%;border-radius:999px;background:currentColor}.incident-title{display:flex;justify-content:space-between;gap:12px}.incident-title span,small,.muted{color:var(--muted)}.empty{border:1px dashed var(--line);border-radius:14px;padding:22px;color:var(--muted);text-align:center}.subscribe{grid-template-columns:minmax(0,1fr) minmax(320px,520px);align-items:center}.subscribe form{display:grid;grid-template-columns:130px minmax(0,1fr) auto;gap:10px}input,select,button{min-height:44px;border:1px solid var(--line);border-radius:10px;font:inherit}input,select{width:100%;background:#fff;color:var(--text);padding:0 12px}button{background:#18212f;color:#fff;padding:0 18px;font-weight:600;cursor:pointer}.notice{border:1px solid #bfdbfe;border-radius:14px;background:#eff6ff;color:#1d4ed8;padding:14px 18px;font-weight:600}.notice.success{border-color:#bbf7d0;background:#f0fdf4;color:var(--ok)}.notice.error{border-color:#fecaca;background:#fef2f2;color:var(--critical)}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#0c1118;--surface:#111821;--surface-2:#151e2a;--line:#263241;--text:#eef4fb;--muted:#9aa8ba;--shadow:none}input,select{background:#0c1118}}
@media (max-width:820px){.page{padding:22px 14px 34px}.hero{padding:24px}.hero-grid,.summary-grid,.subscribe,.subscribe form,.monitor{grid-template-columns:1fr}.section-head,.incident-title{align-items:flex-start;flex-direction:column}.monitor,.incident{gap:12px}}
`;

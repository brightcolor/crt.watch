import { useState } from "react";
import { Copy } from "lucide-react";
import type { CheckResult, Incident, Monitor } from "../api/client";
import { CertificateAuthorityMark } from "../components/CertificateAuthorityMark";
import { StatusPill } from "../components/StatusPill";
import { certificateUnavailableMessage, collectsCertificate } from "../utils/monitorTypes";
import { formatDateTime } from "../utils/date";

type MonitorDetailProps = {
  monitor: Monitor;
  results: CheckResult[];
  incidents: Incident[];
  onBack: () => void;
  onEdit: () => void;
  onCheck: () => void;
  onClone: () => void;
  onToggleEnabled: () => void;
  onDelete: () => void;
  onSslLabs: () => Promise<any>;
  onAck: (id: string, assignee: string, comment: string) => Promise<void>;
  onNote: (id: string, text: string) => Promise<void>;
};

export function MonitorDetail({ monitor, results, incidents, onBack, onEdit, onCheck, onClone, onToggleEnabled, onDelete, onSslLabs, onAck, onNote }: MonitorDetailProps) {
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [sslLabsState, setSslLabsState] = useState({ busy: false, message: "" });
  const [incidentError, setIncidentError] = useState("");
  // A refused acknowledgement or note shows the reason the server gave, such as the role it needs.
  const changeIncident = async (change: () => Promise<void>) => {
    setIncidentError("");
    try {
      await change();
      setNote("");
    } catch (error) {
      setIncidentError(error instanceof Error ? error.message : "The incident could not be changed. Reload the page and try again.");
    }
  };
  const latest = results[0] ?? monitor.latestResult;
  const origin = window.location.origin;
  const statusTag = monitor.tags[0] ?? "all";
  const badgeUrl = `${origin}/public/badge/${monitor.id}.svg`;
  const aliasBadgeUrl = `${badgeUrl}?label=${encodeURIComponent(shortBadgeLabel(monitor.name))}`;
  const statusUrl = `${origin}/public/status/${encodeURIComponent(statusTag)}.html`;
  const markdownBadge = `[![${monitor.name}](${aliasBadgeUrl})](${statusUrl})`;
  const htmlBadge = `<a href="${statusUrl}"><img src="${aliasBadgeUrl}" alt="${escapeHtmlAttr(monitor.name)} status"></a>`;
  const hasCertificateDetails = Boolean(latest?.fingerprintSha256 || latest?.commonName || latest?.validUntil || latest?.tlsVersion || (latest?.chain?.length ?? 0) > 0);
  const certificateExpected = collectsCertificate(monitor.type, monitor.config, monitor.port);
  const canTriggerSslLabs = ["https", "tls", "http", "http_login"].includes(monitor.type) && monitor.port === 443;
  const triggerSslLabs = async () => {
    setSslLabsState({ busy: true, message: "SSL Labs assessment running..." });
    try {
      const result = await onSslLabs();
      setSslLabsState({ busy: false, message: `SSL Labs ${sslLabsSummary(result?.assessment)}` });
    } catch (error) {
      setSslLabsState({ busy: false, message: error instanceof Error ? error.message : "SSL Labs trigger failed." });
    }
  };

  return (
    <section className="content">
      <div className={`detail-hero tone-${monitor.lastStatus.toLowerCase()}`}>
        <div className="detail-head">
          <div className="detail-identity">
            <button className="btn btn-outline-secondary btn-sm detail-back" onClick={onBack}>Back</button>
            <div>
              <div className="detail-title"><h2>{monitor.name}</h2><StatusPill status={monitor.lastStatus} /></div>
              <p>{monitor.host}:{monitor.port} · {monitor.type}</p>
              <small>{monitor.tags.join(", ") || "unlabeled"}</small>
            </div>
          </div>
          {latest?.daysRemaining !== null && latest?.daysRemaining !== undefined && (
            <div className="detail-lifetime">
              <span className="section-label">Certificate</span>
              <strong>{latest.daysRemaining} {Math.abs(latest.daysRemaining) === 1 ? "day" : "days"}</strong>
              <small>{latest.daysRemaining < 0 ? "past expiry" : "until expiry"} · {dateTime(latest.validUntil)}</small>
            </div>
          )}
          <div className="actions detail-actions">
            <button className="btn btn-primary" disabled={!monitor.enabled} onClick={onCheck}>Check now</button>
            {canTriggerSslLabs && <button className="btn btn-outline-secondary" disabled={sslLabsState.busy} onClick={triggerSslLabs}>SSL Labs</button>}
            <button className="btn btn-outline-secondary" onClick={onToggleEnabled}>{monitor.enabled ? "Pause" : "Resume"}</button>
            <button className="btn btn-outline-secondary" onClick={onClone}><Copy size={16} /> Clone</button>
            <button className="btn btn-outline-secondary" onClick={onEdit}>Edit</button>
            <span className="action-divider" aria-hidden="true" />
            <button className="btn btn-outline-danger" onClick={() => { if (confirm(`Delete monitor "${monitor.name}"?`)) onDelete(); }}>Delete</button>
          </div>
        </div>
        {sslLabsState.message && <p className="muted">{sslLabsState.message}</p>}
      </div>
      {hasCertificateDetails ? <div className="grid two">
          <Panel title="Certificate">
            <CertificateAuthorityMark issuer={latest?.issuer} />
            <Info label="Common name" value={latest?.commonName} />
            <Info label="Issuer" value={latest?.issuer} />
            <Info label="Serial number" value={latest?.serialNumber} />
            <Info label="SHA256 fingerprint" value={latest?.fingerprintSha256} />
            <Info label="Valid from" value={dateTime(latest?.validFrom)} />
            <Info label="Valid until" value={dateTime(latest?.validUntil)} />
            <Info label="SANs" value={latest?.subjectAltNames.join(", ")} />
          </Panel>
          <ResultPanel latest={latest} title="TLS" />
        </div> : <div className="grid two">
          <Panel title={certificateExpected ? "Certificate unavailable" : "Service check"}>
            <EmptyHint title={certificateExpected ? "No certificate details in the latest result" : "This monitor does not collect certificates"} text={certificateUnavailableMessage(monitor.type, monitor.config, monitor.port)} />
          </Panel>
          <ResultPanel latest={latest} title="Latest result" />
        </div>}
      {hasCertificateDetails && <Panel title="Certificate chain">
        {(latest?.chain ?? []).length ? (latest?.chain ?? []).map((item, index) => <div className="chain" key={item.fingerprintSha256 ?? index}><strong>{index + 1}. {item.subject}</strong><span>{item.issuer}</span><small>{dateTime(item.validUntil)}</small></div>) : <span className="muted">No certificate chain was returned by the target.</span>}
      </Panel>}
      <DnsPanel result={latest} />
      <Panel title="Embed">
        <p className="muted">The badge shows this monitor's state while a published status page in Operations covers it; otherwise it reads unknown.</p>
        <EmbedRow label="Badge URL" value={badgeUrl} />
        <EmbedRow label="Alias badge URL" value={aliasBadgeUrl} />
        <EmbedRow label="Markdown" value={markdownBadge} />
        <EmbedRow label="HTML" value={htmlBadge} />
      </Panel>
      <Panel title="Incident timeline">
        <div className="stack-list">
          {incidents.map((incident) => <div key={incident.id}><StatusPill status={incident.status} /><span>{incident.message}</span><small>{dateTime(incident.startedAt)} - {incident.resolvedAt ? dateTime(incident.resolvedAt) : "open"}{incident.acknowledgedAt ? ` - ack ${dateTime(incident.acknowledgedAt)}` : ""}</small></div>)}
          {!incidents.length && <span className="muted">No incidents recorded for this monitor.</span>}
        </div>
        {incidents[0] && !incidents[0].resolvedAt && <div className="grid two">
          <label>Assignee<input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="Team or person" /></label>
          <label>Required comment<input required value={note} onChange={(e) => setNote(e.target.value)} placeholder="What happened and what was checked?" /></label>
          <div className="actions"><button className="btn btn-primary" disabled={!note.trim()} onClick={() => changeIncident(() => onAck(incidents[0].id, assignee, note))}>Acknowledge with comment</button>
          <button className="btn btn-outline-secondary" disabled={!note.trim()} onClick={() => changeIncident(() => onNote(incidents[0].id, note))}>Add note</button></div>
        </div>}
        {incidentError && <p className="error" role="status">{incidentError}</p>}
        {incidents[0]?.notes?.length > 0 && <div className="stack-list">{incidents[0].notes.map((item) => <div key={item.id}><strong>{item.author}</strong><span>{item.text}</span><small>{dateTime(item.createdAt)}</small></div>)}</div>}
      </Panel>
      <Panel title="Check history">
        <div className="stack-list rows-log">{results.map((result) => <div key={result.id}><StatusPill status={result.status} /><span>{dateTime(result.checkedAt)}</span><span>{result.message}</span></div>)}</div>
      </Panel>
    </section>
  );
}

function Panel({ title, children }: any) {
  return <div className="panel"><h3>{title}</h3>{children}</div>;
}

function ResultPanel({ latest, title }: { latest?: CheckResult | null; title: string }) {
  return <Panel title={title}>
    <Info label="Status reason" value={resultReason(latest)} />
    <Info label="Security grade" value={latest?.tlsGrade ? `${latest.tlsGrade} (${latest.tlsScore ?? 0}/100)` : "-"} />
    <GradeReasons reasons={latest?.tlsGradeReasons ?? []} />
    <Info label="SSL Labs grade" value={latest?.sslLabsGrade ? `${latest.sslLabsGrade} (${latest.sslLabsStatus ?? "ready"})` : latest?.sslLabsStatus} />
    <Info label="SSL Labs check" value={dateTime(latest?.sslLabsCheckedAt)} />
    {latest?.sslLabsUrl && <Info label="SSL Labs URL" value={latest.sslLabsUrl} />}
    <Info label="Version" value={latest?.tlsVersion} />
    <Info label="Supported versions" value={(latest?.tlsSupportedVersions ?? []).join(", ")} />
    <Info label="Cipher suite" value={latest?.cipherSuite} />
    <Info label="Flapping" value={latest?.flapping ? "Detected" : "No"} />
    <Info label="Last check" value={dateTime(latest?.checkedAt)} />
    <Info label="Duration" value={latest ? `${latest.durationMs} ms` : ""} />
    <Info label="Problems" value={[...(latest?.problems ?? []), ...(latest?.sslLabsFindings ?? [])].join("; ") || "None"} />
  </Panel>;
}

function GradeReasons({ reasons }: { reasons: Array<{ reason: string; points: number }> }) {
  if (!reasons.length) return <Info label="TLS grade reasons" value="No deductions recorded." />;
  return <div className="info stacked-info"><span>TLS grade reasons</span><span className="reason-list">{reasons.map((item) => <span className="pill warn" key={item.reason}>{item.reason}<b>-{item.points}</b></span>)}</span></div>;
}

function resultReason(latest?: CheckResult | null) {
  if (!latest) return "No check result has been recorded yet.";
  if (latest.message) return latest.message;
  if (latest.status === "OK") return "Last check completed without active problems.";
  return latest.problems[0] ?? "No detailed reason was recorded for this status.";
}

function DnsPanel({ result }: { result?: CheckResult | null }) {
  const dns = result?.dns;
  if (!dns) {
    return <Panel title="DNS resolution"><span className="muted">No DNS resolution sample has been collected yet. Run a check to resolve the hostname and compare public resolvers.</span></Panel>;
  }
  return <Panel title="DNS resolution">
    <Info label="Resolved IPs" value={dns.addresses.join(", ")} />
    <Info label="Authoritative zone" value={dns.authoritativeZone} />
    <Info label="Authoritative nameservers" value={dns.authoritativeNameservers.join(", ")} />
    <Info label="DNS checked" value={`${dateTime(dns.checkedAt)}${dns.fresh ? "" : " (cached)"}`} />
    {!!dns.mismatches.length && <div className="callout callout-warning"><strong>Resolver differences detected</strong><p>{dns.mismatches.join(" ")}</p></div>}
    <div className="stack-list rows-kv">
      {dns.checks.map((check) => (
        <div key={`${check.kind}-${check.name}`}>
          <strong>{check.name}</strong>
          <span>{check.addresses.join(", ") || check.error || "No records"}</span>
          {!!check.servers.length && <small>{check.servers.join(", ")}</small>}
        </div>
      ))}
    </div>
  </Panel>;
}

function EmptyHint({ title, text }: { title: string; text: string }) {
  return <div className="empty-state compact"><strong>{title}</strong><span className="muted">{text}</span></div>;
}

function Info({ label, value }: { label: string; value?: string | null }) {
  return <div className="info"><span>{label}</span><strong>{value || "-"}</strong></div>;
}

function EmbedRow({ label, value }: { label: string; value: string }) {
  return <div className="info embed-row"><span>{label}</span><code>{value}</code><button className="btn btn-sm btn-outline-secondary" type="button" onClick={() => navigator.clipboard?.writeText(value)}>Copy</button></div>;
}

const dateTime = formatDateTime;
const shortBadgeLabel = (value: string) => value.trim() || "Monitor";
const escapeHtmlAttr = (value: string) => value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const sslLabsSummary = (assessment: any) => assessment?.sslLabsGrade ? `grade ${assessment.sslLabsGrade}` : assessment?.sslLabsStatus ? `status ${assessment.sslLabsStatus}` : "assessment completed";

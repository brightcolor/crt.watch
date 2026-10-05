import { useEffect, useState } from "react";
import { api } from "../api/client";
import { TagInput } from "../components/TagInput";
import { MaintenanceWindowBuilder } from "../components/MaintenanceWindowBuilder";
import { formatDateTime } from "../utils/date";
import { humanize } from "../utils/labels";

export function Operations({ liveRefreshKey = 0 }: { liveRefreshKey?: number }) {
  const [maintenance, setMaintenance] = useState<any>({ windows: [] });
  const [tlsPolicy, setTlsPolicy] = useState<any>({ profile: "modern", minimumTlsVersion: "TLSv1.2", weakCipherPenalty: 40, requireSan: true, intensiveScan: true });
  const [sslLabs, setSslLabs] = useState<any>({ enabled: false, registeredEmail: "", intervalHours: 24, maxAgeHours: 24, timeoutSeconds: 90, startNewScans: false, publishResults: false });
  const [sslLabsRegistration, setSslLabsRegistration] = useState({ firstName: "", lastName: "", email: "", organization: "" });
  const [sslLabsTrigger, setSslLabsTrigger] = useState({ host: "", startNewScan: true });
  const [sslLabsTriggerResult, setSslLabsTriggerResult] = useState<any>(null);
  const [sslLabsStatus, setSslLabsStatus] = useState("");
  const [statusPages, setStatusPages] = useState<any>({ pages: [] });
  const [discovery, setDiscovery] = useState<any>({ enabled: false, intervalHours: 24, domains: [], suggestions: [] });
  const [backupSettings, setBackupSettings] = useState<any>({ enabled: false, intervalHours: 24, keep: 7 });
  const [backups, setBackups] = useState<any[]>([]);
  const [tokens, setTokens] = useState<any[]>([]);
  const [deliveries, setDeliveries] = useState<any[]>([]);
  const [auditLog, setAuditLog] = useState<any[]>([]);
  const [tokenResult, setTokenResult] = useState("");
  const [route, setRoute] = useState({ name: "", tags: [] as string[], window: "daily 22:00-23:00" });
  const [page, setPage] = useState({ slug: "", title: "", description: "", logoUrl: "", tags: [] as string[], hideHostnames: false });
  const [tokenName, setTokenName] = useState("");
  const [tokenScope, setTokenScope] = useState("read");

  const load = async () => {
    const [m, t, ssl, s, d, b, backupList, tokenList, deliveryList, auditList] = await Promise.all([
      api.request<any>("/settings/maintenance"),
      api.request<any>("/settings/tls-policy"),
      api.request<any>("/settings/ssl-labs"),
      api.request<any>("/settings/status-pages"),
      api.request<any>("/settings/discovery"),
      api.request<any>("/settings/backups"),
      // Backup files and API tokens belong to platform administrators; others see empty lists.
      api.request<any[]>("/backups").catch(() => []),
      api.request<any[]>("/api-tokens").catch(() => []),
      api.request<any[]>("/deliveries"),
      api.request<any[]>("/audit-log").catch(() => [])
    ]);
    setMaintenance(m); setTlsPolicy(t); setSslLabs(ssl); setStatusPages(s); setDiscovery(d); setBackupSettings(b); setBackups(backupList); setTokens(tokenList); setDeliveries(deliveryList); setAuditLog(auditList);
  };
  useEffect(() => { void load(); }, [liveRefreshKey]);

  const save = async (path: string, body: any) => { await api.request(path, { method: "PUT", body: JSON.stringify(body) }); await load(); };
  const addMaintenance = () => {
    const windows = [...maintenance.windows, { id: crypto.randomUUID(), ...route, enabled: true }];
    void save("/settings/maintenance", { windows });
    setRoute({ name: "", tags: [], window: "daily 22:00-23:00" });
  };
  const addStatusPage = () => {
    const pages = [...statusPages.pages, { id: crypto.randomUUID(), ...page, enabled: true }];
    void save("/settings/status-pages", { pages });
    setPage({ slug: "", title: "", description: "", logoUrl: "", tags: [], hideHostnames: false });
  };
  const createToken = async () => {
    const created = await api.request<any>("/api-tokens", { method: "POST", body: JSON.stringify({ name: tokenName, scopes: tokenScope === "write" ? ["read", "write"] : ["read"] }) });
    setTokenResult(created.token);
    setTokenName("");
    await load();
  };
  const importDiscovery = async (items?: any[]) => {
    await api.request("/discovery/import", { method: "POST", body: JSON.stringify({ monitors: items }) });
    await load();
  };
  const registerSslLabs = async () => {
    setSslLabsStatus("Registering with SSL Labs...");
    try {
      const result = await api.request<any>("/ssl-labs/register", { method: "POST", body: JSON.stringify(sslLabsRegistration) });
      setSslLabs(result.settings);
      setSslLabsStatus("SSL Labs registration completed. The registered email was saved.");
    } catch (error) {
      setSslLabsStatus(error instanceof Error ? error.message : "SSL Labs registration failed.");
    }
  };
  const triggerSslLabs = async () => {
    setSslLabsStatus("Triggering SSL Labs assessment...");
    setSslLabsTriggerResult(null);
    try {
      const result = await api.request<any>("/ssl-labs/trigger", { method: "POST", body: JSON.stringify(sslLabsTrigger) });
      setSslLabsTriggerResult(result);
      setSslLabsStatus(`SSL Labs assessment completed for ${result.host}: ${sslLabsSummary(result.assessment)}.`);
    } catch (error) {
      setSslLabsStatus(error instanceof Error ? error.message : "SSL Labs trigger failed.");
    }
  };

  return (
    <section className="content">
      <div className="flow">
        <div className="panel">
          <h3>Maintenance windows</h3>
          <label>Name<input value={route.name} onChange={(e) => setRoute((current) => ({ ...current, name: e.target.value }))} /></label>
          <TagInput value={route.tags} onChange={(tags) => setRoute((current) => ({ ...current, tags }))} />
          <MaintenanceWindowBuilder onUse={(value) => setRoute((current) => ({ ...current, window: value }))} buttonLabel="Use as window" />
          <label>Window<input value={route.window} onChange={(e) => setRoute((current) => ({ ...current, window: e.target.value }))} placeholder="daily 22:00-23:00" /></label>
          <button className="btn btn-primary" onClick={addMaintenance}>Add window</button>
          {maintenance.windows.map((item: any) => <Row key={item.id} title={item.name} detail={`${item.tags.join(", ")} - ${item.window}`} onDelete={() => save("/settings/maintenance", { windows: maintenance.windows.filter((entry: any) => entry.id !== item.id) })} />)}
        </div>
        <div className="panel">
          <h3>TLS policy profile</h3>
          <label>Profile<select value={tlsPolicy.profile} onChange={(e) => setTlsPolicy({ ...tlsPolicy, profile: e.target.value })}><option value="modern">Modern</option><option value="strict">Strict</option><option value="legacy">Legacy tolerated</option></select></label>
          <label>Minimum TLS<select value={tlsPolicy.minimumTlsVersion} onChange={(e) => setTlsPolicy({ ...tlsPolicy, minimumTlsVersion: e.target.value })}>{["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"].map((item) => <option key={item}>{item}</option>)}</select></label>
          <label>Weak cipher penalty<input type="number" min="0" max="80" value={tlsPolicy.weakCipherPenalty} onChange={(e) => setTlsPolicy({ ...tlsPolicy, weakCipherPenalty: Number(e.target.value) })} /></label>
          <label><input type="checkbox" checked={tlsPolicy.requireSan} onChange={(e) => setTlsPolicy({ ...tlsPolicy, requireSan: e.target.checked })} /> Require SAN extension</label>
          <label><input type="checkbox" checked={tlsPolicy.intensiveScan ?? true} onChange={(e) => setTlsPolicy({ ...tlsPolicy, intensiveScan: e.target.checked })} /> Probe supported TLS versions</label>
          <button className="btn btn-primary" onClick={() => save("/settings/tls-policy", tlsPolicy)}>Save TLS policy</button>
        </div>
        <div className="panel">
          <h3>SSL Labs assessment</h3>
          <p className="muted">Optional external SSL Labs v4 checks for public HTTPS hosts on port 443. crt.watch keeps local checks as the source of truth.</p>
          <label><input type="checkbox" checked={sslLabs.enabled} onChange={(e) => setSslLabs({ ...sslLabs, enabled: e.target.checked })} /> Enabled</label>
          <label>Registered email<input value={sslLabs.registeredEmail ?? ""} onChange={(e) => setSslLabs({ ...sslLabs, registeredEmail: e.target.value })} placeholder="ops@example.com" /></label>
          <label>Interval hours<input type="number" min="24" value={sslLabs.intervalHours} onChange={(e) => setSslLabs({ ...sslLabs, intervalHours: Number(e.target.value) })} /></label>
          <label>Cache max age hours<input type="number" min="1" value={sslLabs.maxAgeHours} onChange={(e) => setSslLabs({ ...sslLabs, maxAgeHours: Number(e.target.value) })} /></label>
          <label>Timeout seconds<input type="number" min="15" max="300" value={sslLabs.timeoutSeconds} onChange={(e) => setSslLabs({ ...sslLabs, timeoutSeconds: Number(e.target.value) })} /></label>
          <label><input type="checkbox" checked={sslLabs.startNewScans} onChange={(e) => setSslLabs({ ...sslLabs, startNewScans: e.target.checked })} /> Start fresh scans when due</label>
          <label><input type="checkbox" checked={sslLabs.publishResults} onChange={(e) => setSslLabs({ ...sslLabs, publishResults: e.target.checked })} /> Publish on SSL Labs boards</label>
          <button className="btn btn-primary" onClick={() => save("/settings/ssl-labs", sslLabs)}>Save SSL Labs</button>
          <div className="form-section">
            <h3>Register SSL Labs API email</h3>
            <p className="muted">Submit the one-time SSL Labs v4 registration and save the returned email for assessments.</p>
            <div className="grid two">
              <label>First name<input value={sslLabsRegistration.firstName} onChange={(e) => setSslLabsRegistration({ ...sslLabsRegistration, firstName: e.target.value })} /></label>
              <label>Last name<input value={sslLabsRegistration.lastName} onChange={(e) => setSslLabsRegistration({ ...sslLabsRegistration, lastName: e.target.value })} /></label>
              <label>Email<input type="email" value={sslLabsRegistration.email} onChange={(e) => setSslLabsRegistration({ ...sslLabsRegistration, email: e.target.value })} /></label>
              <label>Organization<input value={sslLabsRegistration.organization} onChange={(e) => setSslLabsRegistration({ ...sslLabsRegistration, organization: e.target.value })} /></label>
            </div>
            <button className="btn btn-outline-secondary" onClick={registerSslLabs}>Register and use email</button>
            {sslLabsStatus && <p className="muted">{sslLabsStatus}</p>}
          </div>
          <div className="form-section">
            <h3>Trigger assessment</h3>
            <p className="muted">Run an external SSL Labs assessment now for a public HTTPS host on port 443.</p>
            <label>Hostname<input value={sslLabsTrigger.host} onChange={(e) => setSslLabsTrigger({ ...sslLabsTrigger, host: e.target.value })} placeholder="example.com" /></label>
            <label><input type="checkbox" checked={sslLabsTrigger.startNewScan} onChange={(e) => setSslLabsTrigger({ ...sslLabsTrigger, startNewScan: e.target.checked })} /> Start a fresh scan</label>
            <button className="btn btn-outline-secondary" onClick={triggerSslLabs}>Trigger SSL Labs</button>
            {sslLabsTriggerResult?.assessment && <div className="callout callout-info"><strong>{sslLabsSummary(sslLabsTriggerResult.assessment)}</strong><p>{(sslLabsTriggerResult.assessment.sslLabsFindings ?? []).join(" ") || "No SSL Labs findings returned."}</p></div>}
          </div>
        </div>
        <div className="panel">
          <h3>Status pages</h3>
          <label>Slug<input value={page.slug} onChange={(e) => setPage((current) => ({ ...current, slug: e.target.value.toLowerCase() }))} placeholder="public-prod" /></label>
          <label>Title<input value={page.title} onChange={(e) => setPage((current) => ({ ...current, title: e.target.value }))} /></label>
          <label>Description<input value={page.description} onChange={(e) => setPage((current) => ({ ...current, description: e.target.value }))} /></label>
          <label>Logo URL<input value={page.logoUrl} onChange={(e) => setPage((current) => ({ ...current, logoUrl: e.target.value }))} /></label>
          <TagInput value={page.tags} onChange={(tags) => setPage((current) => ({ ...current, tags }))} />
          <label><input type="checkbox" checked={page.hideHostnames} onChange={(e) => setPage((current) => ({ ...current, hideHostnames: e.target.checked }))} /> Hide hostnames</label>
          <button className="btn btn-primary" onClick={addStatusPage}>Add status page</button>
          {statusPages.pages.map((item: any) => <Row key={item.id} title={item.title} detail={`/public/status/${item.slug}.html - ${item.tags.join(", ")}`} onDelete={() => save("/settings/status-pages", { pages: statusPages.pages.filter((entry: any) => entry.id !== item.id) })} />)}
        </div>
        <div className="panel">
          <h3>Discovery job</h3>
          <label><input type="checkbox" checked={discovery.enabled} onChange={(e) => setDiscovery({ ...discovery, enabled: e.target.checked })} /> Enabled</label>
          <label>Interval hours<input type="number" min="1" value={discovery.intervalHours} onChange={(e) => setDiscovery({ ...discovery, intervalHours: Number(e.target.value) })} /></label>
          <label>Domains<textarea value={(discovery.domains ?? []).join("\n")} onChange={(e) => setDiscovery({ ...discovery, domains: e.target.value.split(/\s+/).filter(Boolean) })} /></label>
          <div className="actions"><button className="btn btn-primary" onClick={() => save("/settings/discovery", discovery)}>Save discovery</button><button className="btn btn-outline-secondary" onClick={async () => { await api.request("/discovery/run", { method: "POST", body: "{}" }); await load(); }}>Run now</button></div>
          {!!(discovery.suggestions ?? []).length && <button className="btn btn-outline-secondary" onClick={() => importDiscovery()}>Accept all found monitors</button>}
          <div className="stack-list">{(discovery.suggestions ?? []).slice(0, 12).map((item: any) => <div key={`${item.host}-${item.port}-${item.type}`}><strong>{item.name}</strong><span>{item.host}:{item.port}</span><small>{item.type} - {item.tags.join(", ")}</small><button className="btn btn-outline-secondary btn-sm" onClick={() => importDiscovery([item])}>Accept</button></div>)}</div>
        </div>
        <div className="panel">
          <h3>Database backups</h3>
          <label><input type="checkbox" checked={backupSettings.enabled} onChange={(e) => setBackupSettings({ ...backupSettings, enabled: e.target.checked })} /> Scheduled backups</label>
          <label>Interval hours<input type="number" min="1" value={backupSettings.intervalHours} onChange={(e) => setBackupSettings({ ...backupSettings, intervalHours: Number(e.target.value) })} /></label>
          <label>Keep backups<input type="number" min="1" max="100" value={backupSettings.keep} onChange={(e) => setBackupSettings({ ...backupSettings, keep: Number(e.target.value) })} /></label>
          <div className="actions"><button className="btn btn-primary" onClick={() => save("/settings/backups", backupSettings)}>Save backups</button><button className="btn btn-outline-secondary" onClick={async () => { await api.request("/backups/run", { method: "POST", body: "{}" }); await load(); }}>Run backup</button></div>
          {backups.map((item) => <div className="channel" key={item.name}><strong>{item.name}</strong><span>{Math.round(item.size / 1024)} KB</span><div className="actions"><a className="btn btn-outline-secondary" href={`/api/backups/${item.name}`}>Download</a><button className="btn btn-outline-danger" onClick={async () => { await api.request(`/backups/${item.name}`, { method: "DELETE" }); await load(); }}>Delete</button></div></div>)}
        </div>
        <div className="panel">
          <h3>API tokens</h3>
          <label>Name<input value={tokenName} onChange={(e) => setTokenName(e.target.value)} /></label>
          <label>Scope<select value={tokenScope} onChange={(e) => setTokenScope(e.target.value)}><option value="read">Read only</option><option value="write">Read and write</option></select></label>
          <button className="btn btn-primary" onClick={createToken}>Create token</button>
          {tokenResult && <label>New token<input readOnly value={tokenResult} onFocus={(e) => e.currentTarget.select()} /></label>}
          {tokens.map((item) => <Row key={item.id} title={item.name} detail={`created ${dateTime(item.createdAt)}${item.lastUsedAt ? ` - used ${dateTime(item.lastUsedAt)}` : ""}`} onDelete={async () => { await api.request(`/api-tokens/${item.id}`, { method: "DELETE" }); await load(); }} />)}
        </div>
        <div className="panel">
          <h3>Notification delivery log</h3>
          <div className="log-list">{deliveries.slice(0, 25).map((item) => (
            <div className="log-entry" key={item.id}>
              <span className={`pill ${item.deliveryStatus === "sent" ? "pass" : "fail"}`}>{humanize(item.deliveryStatus)}</span>
              <strong>{item.channelName}</strong>
              <span className="muted">{humanize(item.provider)}</span>
              <small>{item.error || item.message}</small>
            </div>
          ))}</div>
        </div>
        <div className="panel">
          <h3>Audit log</h3>
          <p className="muted">Organization and team management actions, most recent first.</p>
          <div className="stack-list">
            {auditLog.length === 0 && <p className="muted">No audit entries yet.</p>}
            {auditLog.map((item) => <div key={item.id}><strong>{item.action}</strong><span>{item.actorEmail ?? "system"}</span><small>{dateTime(item.createdAt)}</small></div>)}
          </div>
        </div>
      </div>
    </section>
  );
}

function Row({ title, detail, onDelete }: { title: string; detail: string; onDelete: () => void | Promise<void> }) {
  return <div className="channel"><strong>{title}</strong><span>{detail}</span><button className="btn btn-outline-danger" onClick={onDelete}>Delete</button></div>;
}

const dateTime = formatDateTime;

const sslLabsSummary = (assessment: any) => [
  assessment?.sslLabsGrade ? `grade ${assessment.sslLabsGrade}` : null,
  assessment?.sslLabsStatus ? `status ${assessment.sslLabsStatus}` : null
].filter(Boolean).join(", ") || "queued";

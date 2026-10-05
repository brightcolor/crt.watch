import type { Monitor } from "../api/client";
import { Boxes } from "lucide-react";
import { StatusPill } from "../components/StatusPill";
import { EmptyState } from "../components/EmptyState";

export function Applications({ monitors, onSelect }: { monitors: Monitor[]; onSelect: (id: string) => void }) {
  const groups = Array.from(new Set(monitors.flatMap((monitor) => monitor.tags))).sort().map((tag) => ({
    tag,
    monitors: monitors.filter((monitor) => monitor.tags.includes(tag))
  }));
  const origin = window.location.origin;
  const combinations = tagCombinations(groups.map((group) => group.tag));

  return (
    <section className="content">
      <p className="page-intro">Labels group related checks into application rollups, status pages, and badges. The status and badge addresses answer once a status page with the same labels is published in Operations; until then they report that nothing is published there.</p>
      <div className="flow">
        {!groups.length && <EmptyState
          icon={<Boxes size={24} />}
          title="Group your checks into applications"
          text="Give monitors a label such as production or mail, and crt.watch rolls them up here with a shared status page and badges you can embed."
          hint="Labels are set on each monitor, and a monitor can carry several."
        />}
        {groups.map((group) => {
          const status = rollup(group.monitors);
          const key = encodeURIComponent(group.tag);
          const statusUrl = `${origin}/public/status/${key}.html`;
          const badgeUrl = `${origin}/public/badge/tags/${key}.svg`;
          const aliasBadgeUrl = `${badgeUrl}?label=${encodeURIComponent(group.tag)}`;
          return (
            <div className="panel" key={group.tag}>
              <div className="detail-head">
                <div><h3>{group.tag}</h3><small>{group.monitors.length} {group.monitors.length === 1 ? "check" : "checks"}</small></div>
                <StatusPill status={status} />
              </div>
              <div className="stack-list">
                {group.monitors.map((monitor) => <div className="stack-row" role="button" tabIndex={0} key={monitor.id} onClick={() => onSelect(monitor.id)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(monitor.id); } }}><StatusPill status={monitor.lastStatus} /><strong>{monitor.name}</strong><span>{monitor.host}:{monitor.port}</span></div>)}
              </div>
              <EmbedRow label="Status" value={statusUrl} />
              <EmbedRow label="Badge" value={badgeUrl} />
              <EmbedRow label="Alias badge" value={aliasBadgeUrl} />
            </div>
          );
        })}
      </div>
      {combinations.length > 0 && <div className="panel">
        <h3>Combined status pages</h3>
        <p className="muted">Use combined labels when a public status page should include only checks that match all selected labels.</p>
        <div className="embed-grid">
          {combinations.map((group) => {
            const key = group.map(encodeURIComponent).join("+");
            const label = group.join(" + ");
            const html = `${origin}/public/status/${key}.html`;
            const badge = `${origin}/public/badge/tags/${key}.svg`;
            const aliasBadge = `${badge}?label=${encodeURIComponent(label)}`;
            const iframe = `<iframe src="${html}" title="crt.watch ${label}" loading="lazy"></iframe>`;
            const markdown = `[![${label}](${aliasBadge})](${html})`;
            return <div className="embed-card" key={key}><strong>{label}</strong><code>{html}</code><div className="actions"><button className="btn btn-outline-secondary btn-sm" onClick={() => navigator.clipboard?.writeText(html)}>URL</button><button className="btn btn-outline-secondary btn-sm" onClick={() => navigator.clipboard?.writeText(iframe)}>iframe</button><button className="btn btn-outline-secondary btn-sm" onClick={() => navigator.clipboard?.writeText(markdown)}>Badge</button></div></div>;
          })}
        </div>
      </div>}
    </section>
  );
}

function EmbedRow({ label, value }: { label: string; value: string }) {
  return <div className="info"><span>{label}</span><code>{value}</code><button className="btn btn-outline-secondary btn-sm" type="button" onClick={() => navigator.clipboard?.writeText(value)}>Copy</button></div>;
}

const rollup = (monitors: Monitor[]) =>
  monitors.some((monitor) => monitor.lastStatus === "DOWN" || monitor.lastStatus === "CRITICAL") ? "CRITICAL" :
    monitors.some((monitor) => monitor.lastStatus === "WARNING") ? "WARNING" :
      monitors.some((monitor) => monitor.lastStatus === "PAUSED") ? "PAUSED" :
        monitors.some((monitor) => monitor.lastStatus === "UNKNOWN") ? "UNKNOWN" : "OK";

const tagCombinations = (tags: string[]) => [
  ...tags.map((tag) => [tag]),
  ...tags.flatMap((left, index) => tags.slice(index + 1).map((right) => [left, right]))
];

import { useEffect, useMemo, useState } from "react";
import { Activity, BarChart3, Bell, Boxes, Check, ChevronsUpDown, Download, LogOut, Menu, Plus, Search, Settings, UserCircle, Users, Upload } from "lucide-react";
import { BrandMark } from "./BrandMark";
import type { Monitor } from "../api/client";
import { humanize } from "../utils/labels";

const navItems = [
  { page: "dashboard", label: "Dashboard", icon: Activity },
  { page: "applications", label: "Applications", icon: Boxes },
  { page: "settings", label: "Alerts", icon: Bell },
  { page: "operations", label: "Operations", icon: Settings },
  { page: "reports", label: "Reports", icon: BarChart3 },
  { page: "import", label: "Import", icon: Upload },
  { page: "tenants", label: "Organizations", icon: Boxes },
  { page: "users", label: "Users", icon: Users }
];

/* The label above the heading names the area, so it says something the heading
   does not repeat. */
const areaByPage: Record<string, string> = {
  dashboard: "Monitoring",
  applications: "Monitoring",
  reports: "Monitoring",
  settings: "Configuration",
  operations: "Configuration",
  import: "Configuration",
  tenants: "Administration",
  users: "Administration",
  profile: "Account"
};

const areaFor = (page: string) => areaByPage[page] ?? "Monitoring";

export function Layout({ children, page, pageTitle, onNew, theme, themeMode, setThemeMode, onPage, version, stats = {}, monitors = [], onSelectMonitor, tenants = [], tenantId, onTenant, teams = [], teamId, onTeam, user, impersonator, onStopImpersonation, onProfile, onLogout }: any) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [search, setSearch] = useState("");
  const critical = (stats.critical ?? 0) + (stats.down ?? 0);
  const currentTenant = tenants.find((item: any) => item.tenantId === tenantId) ?? tenants[0];
  const currentTeam = teams.find((item: any) => item.id === teamId);
  const matches = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return [];
    return monitors
      .filter((monitor: Monitor) => [monitor.name, monitor.host, monitor.type, monitor.tags.join(" ")].join(" ").toLowerCase().includes(term))
      .slice(0, 8);
  }, [monitors, search]);

  useEffect(() => {
    if (!statusOpen && !profileOpen && !workspaceOpen) return;
    const close = (event: MouseEvent) => {
      if ((event.target as HTMLElement).closest(".status-dropdown, .profile-dropdown, .workspace")) return;
      setStatusOpen(false);
      setProfileOpen(false);
      setWorkspaceOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setStatusOpen(false);
      setProfileOpen(false);
      setWorkspaceOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", escape);
    };
  }, [statusOpen, profileOpen, workspaceOpen]);

  const navigate = (nextPage: string) => {
    setSidebarOpen(false);
    onPage(nextPage);
  };
  const toggleSidebar = () => {
    if (window.matchMedia("(max-width: 991.98px)").matches) {
      setSidebarOpen((current) => !current);
      return;
    }
    setSidebarCollapsed((current) => !current);
  };
  const jumpToMonitor = (id: string) => {
    setSearch("");
    onSelectMonitor?.(id);
  };

  return (
    <div className={`app-wrapper layout-fixed sidebar-expand-lg sidebar-mini crtwatch-adminlte${sidebarOpen ? " sidebar-open" : ""}${sidebarCollapsed ? " sidebar-collapse" : ""}`}>
      {sidebarOpen && <button className="sidebar-backdrop" type="button" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
      <nav className="app-header navbar navbar-expand bg-body border-bottom">
        <div className="container-fluid gap-2">
          <button className="nav-link sidebar-toggle" type="button" aria-label="Toggle navigation" onClick={toggleSidebar}>
            <Menu size={20} />
          </button>
          <form className="header-search" onSubmit={(event) => { event.preventDefault(); if (matches[0]) jumpToMonitor(matches[0].id); }}>
            <Search size={16} />
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Jump to monitor, host, or label" />
            {!!matches.length && (
              <div className="header-search-results list-group">
                {matches.map((monitor: Monitor) => (
                  <button className="list-group-item list-group-item-action" type="button" key={monitor.id} onClick={() => jumpToMonitor(monitor.id)}>
                    <strong>{monitor.name}</strong>
                    <span>{monitor.host}:{monitor.port} - {monitor.lastStatus}</span>
                  </button>
                ))}
              </div>
            )}
          </form>
          <div className="header-actions">
            {impersonator && <button className="btn btn-outline-warning btn-sm" type="button" onClick={onStopImpersonation} title={`Signed in as ${user?.email}`}>
              Stop impersonation
            </button>}
            <div className="nav-item status-dropdown">
              <button className="btn btn-outline-secondary btn-sm btn-icon header-bell" type="button" onClick={() => setStatusOpen((current) => !current)} aria-expanded={statusOpen} aria-label="Operations status" title="Operations status">
                <Bell size={16} />
                {critical > 0 && <span className="bell-count">{critical}</span>}
              </button>
              {statusOpen && <StatusMenu stats={stats} onPage={(next: string) => { setStatusOpen(false); navigate(next); }} />}
            </div>
            <button className="btn btn-primary btn-sm" type="button" onClick={onNew}><Plus size={16} /> New monitor</button>
            <div className="nav-item profile-dropdown">
              <button className="avatar-button" type="button" onClick={() => setProfileOpen((current) => !current)} aria-expanded={profileOpen} aria-label={user?.email ?? "Account"} title={user?.email ?? "Account"}>
                <span className="avatar">{initials(user?.email)}</span>
              </button>
              {profileOpen && <div className="profile-menu">
                <div className="menu-head">
                  <span className="avatar avatar-lg">{initials(user?.email)}</span>
                  <div>
                    <strong>{user?.email}</strong>
                    <small>{humanize(user?.role)}</small>
                  </div>
                </div>
                <div className="menu-section">
                  <span className="section-label">Appearance</span>
                  <div className="segmented" role="group" aria-label="Color mode">
                    {themeOptions.map((option) => (
                      <button
                        type="button"
                        className={themeMode === option.value ? "active" : ""}
                        key={option.value}
                        aria-pressed={themeMode === option.value}
                        onClick={() => setThemeMode?.(option.value)}
                      >{option.label}</button>
                    ))}
                  </div>
                </div>
                <div className="menu-list">
                  <button type="button" onClick={() => { setProfileOpen(false); onProfile?.(); }}><UserCircle size={16} /> Account settings</button>
                  <button type="button" onClick={() => { setProfileOpen(false); onLogout?.(); }}><LogOut size={16} /> Log out</button>
                </div>
              </div>}
            </div>
          </div>
        </div>
      </nav>
      <aside className="app-sidebar">
        <div className="sidebar-brand">
          <button className="brand-link" type="button" onClick={() => navigate("dashboard")} title="crt.watch">
            <span className="brand-image"><BrandMark size={19} /></span>
            <span className="brand-text">crt.watch</span>
          </button>
        </div>
        <div className="workspace">
          <button
            className="workspace-button"
            type="button"
            onClick={() => setWorkspaceOpen((current) => !current)}
            aria-expanded={workspaceOpen}
            title={currentTenant?.tenant?.name ?? "Workspace"}
          >
            <span className="workspace-mark">{initials(currentTenant?.tenant?.name)}</span>
            <span className="workspace-copy">
              <strong>{currentTenant?.tenant?.name ?? "Workspace"}</strong>
              <small>{currentTeam?.name ?? humanize(currentTenant?.role)}</small>
            </span>
            <ChevronsUpDown size={14} className="workspace-chevron" />
          </button>
          {workspaceOpen && <div className="workspace-menu">
            <div className="menu-section">
              <span className="section-label">Organization</span>
              <div className="menu-list">
                {tenants.map((item: any) => (
                  <button
                    type="button"
                    className={item.tenantId === tenantId ? "active" : ""}
                    key={item.tenantId}
                    onClick={() => { setWorkspaceOpen(false); onTenant?.(item.tenantId); }}
                  >
                    <span className="workspace-mark sm">{initials(item.tenant.name)}</span>
                    <span className="menu-copy"><strong>{item.tenant.name}</strong><small>{humanize(item.role)}</small></span>
                    {item.tenantId === tenantId && <Check size={15} />}
                  </button>
                ))}
              </div>
            </div>
            {teams.length > 0 && <div className="menu-section">
              <span className="section-label">Team</span>
              <div className="menu-list">
                {teams.map((item: any) => (
                  <button
                    type="button"
                    className={item.id === teamId ? "active" : ""}
                    key={item.id}
                    onClick={() => { setWorkspaceOpen(false); onTeam?.(item.id); }}
                  >
                    <span className="menu-copy"><strong>{item.name}</strong></span>
                    {item.id === teamId && <Check size={15} />}
                  </button>
                ))}
              </div>
            </div>}
            {currentTenant?.tenant && <div className="workspace-usage">
              <div className="usage-head">
                <span>{humanize(currentTenant.tenant.plan)} plan</span>
                <span className="num">{monitors.length} / {currentTenant.tenant.monitorLimit ?? "-"}</span>
              </div>
              <div className="usage-meter"><i style={{ width: `${usageShare(monitors.length, currentTenant.tenant.monitorLimit)}%` }} /></div>
              <small>monitors used</small>
            </div>}
            <div className="menu-list">
              <button type="button" onClick={() => { setWorkspaceOpen(false); navigate("tenants"); }}><Settings size={15} /> Manage organizations</button>
            </div>
          </div>}
        </div>
        <div className="sidebar-wrapper">
          <nav className="mt-2">
            <ul className="nav sidebar-menu flex-column" role="navigation" aria-label="Main navigation">
              {navItems.filter((item) => item.page !== "users" || (user?.role === "super_admin" && !impersonator)).map((item) => <NavItem key={item.page} item={item} active={page === item.page} stats={stats} onClick={() => navigate(item.page)} />)}
              <li className="nav-item"><a className="nav-link" href="/api/export/monitors.json" title="Export"><Download className="nav-icon" size={18} /><p>Export</p></a></li>
            </ul>
          </nav>
        </div>
      </aside>
      <main className="app-main">
        <div className="app-content-header">
          <div className="container-fluid">
            <div className="adminlte-titlebar">
              <div>
                {/* Every page opens the same way: the label with its square,
                    then the name of the page in capitals. */}
                <p className="page-eyebrow">{areaFor(page)}</p>
                <h1>{pageTitle || titleFor(page)}</h1>
              </div>
              {pageTitle && <ol className="breadcrumb mb-0">
                <li className="breadcrumb-item"><button className="btn btn-link p-0" type="button" onClick={() => navigate(page)}>{titleFor(page)}</button></li>
                <li className="breadcrumb-item active" aria-current="page">{pageTitle}</li>
              </ol>}
            </div>
          </div>
        </div>
        <div className="app-content"><div className="container-fluid">{children}</div></div>
      </main>
      <footer className="app-footer"><span>crt.watch v{version || "0.0.0"}</span><span className="ms-auto">Certificate and service monitoring</span></footer>
    </div>
  );
}

function NavItem({ item, active, stats, onClick }: any) {
  const Icon = item.icon;
  const badge = navBadge(item.page, stats);
  return (
    <li className="nav-item">
      <button type="button" className={`nav-link${active ? " active" : ""}`} onClick={onClick} title={item.label}>
        <Icon className="nav-icon" size={18} />
        <p>{item.label}{badge && <span className={`nav-badge ${badge.className}`}>{badge.value}</span>}</p>
      </button>
    </li>
  );
}

function StatusMenu({ stats, onPage }: any) {
  const critical = (stats.critical ?? 0) + (stats.down ?? 0);
  return (
    <div className="status-menu card shadow">
      <div className="card-header"><strong>Operations status</strong></div>
      <div className="list-group list-group-flush">
        <StatusRow label="Healthy" value={stats.ok ?? 0} tone="success" />
        <StatusRow label="Warning" value={stats.warning ?? 0} tone="warning" />
        <StatusRow label="Critical or down" value={critical} tone="danger" />
        <StatusRow label="Paused" value={stats.paused ?? 0} tone="secondary" />
      </div>
      <div className="card-footer d-flex gap-2">
        <button className="btn btn-sm btn-primary" type="button" onClick={() => onPage("dashboard")}>Open dashboard</button>
        <button className="btn btn-sm btn-outline-secondary" type="button" onClick={() => onPage("reports")}>Reports</button>
      </div>
    </div>
  );
}

function StatusRow({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className="list-group-item d-flex align-items-center justify-content-between"><span>{label}</span><span className={`badge text-bg-${tone}`}>{value}</span></div>;
}

const navBadge = (page: string, stats: any) => {
  if (page === "dashboard") {
    const critical = (stats.critical ?? 0) + (stats.down ?? 0);
    if (critical) return { value: critical, className: "danger" };
    if (stats.warning) return { value: stats.warning, className: "warning" };
  }
  return null;
};

export const pageTitles: Record<string, string> = {
  dashboard: "Dashboard",
  settings: "Alerts",
  operations: "Operations",
  reports: "Reports",
  users: "Users",
  tenants: "Organizations",
  import: "Import",
  applications: "Applications",
  profile: "Profile"
};

const titleFor = (page: string) => pageTitles[page] ?? "Dashboard";

const themeOptions = [
  { value: "dark", label: "Dark" },
  { value: "bright", label: "Bright" },
  { value: "auto", label: "System" }
];

/* Two letters stand in for an avatar: the first letters of a name, or the
   first two of an email's local part. */
const initials = (value?: string) => {
  if (!value) return "?";
  const name = value.split("@")[0].replace(/[._-]+/g, " ").trim();
  const parts = name.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
};

const usageShare = (used: number, limit?: number) =>
  limit && limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;

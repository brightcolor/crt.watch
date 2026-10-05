import React, { useEffect, useState } from "react";
import { createRoot, hydrateRoot } from "react-dom/client";
import { api, Monitor, CheckResult, Incident, StatusSubscription, Team, TeamMembership, TenantInvite, TenantMembership, UserAlertSettings } from "./api/client";
import { Layout, pageTitles } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { FrontPage } from "./pages/FrontPage";
import { Login } from "./pages/Login";
import { Register } from "./pages/Register";
import { MonitorDetail } from "./pages/MonitorDetail";
import { MonitorForm } from "./pages/MonitorForm";
import { Settings } from "./pages/Settings";
import { BulkImport } from "./pages/BulkImport";
import { UsersPage } from "./pages/Users";
import { Applications } from "./pages/Applications";
import { Operations } from "./pages/Operations";
import { Reports } from "./pages/Reports";
import { TenantsPage } from "./pages/Tenants";
import { Profile } from "./pages/Profile";
import { BootScreen } from "./components/Skeleton";
import { useLiveRefresh } from "./hooks/useLiveRefresh";
import { applyStatusFavicon } from "./utils/favicon";
import { APP_PREFIX, parseRoute, pathForPage, pathForView } from "./utils/routes";
import "./styles/app.css";

/* When the server rendered the front page, it inlines the same configuration
   it rendered with, as a JSON data block that the Content Security Policy lets
   through. Starting from it means the client's first render matches the markup
   already on the page, so React hydrates it instead of throwing it away and
   rebuilding after a round trip. */
type BootConfig = { setupRequired: boolean; frontPageEnabled: boolean; publicRegistrationEnabled: boolean };
const readBootConfig = (): BootConfig | null => {
  const text = document.getElementById("crtwatch-boot")?.textContent;
  if (!text) return null;
  try {
    return JSON.parse(text) as BootConfig;
  } catch {
    return null;
  }
};
const boot = readBootConfig();

const initialThemeMode = (() => {
  const stored = localStorage.getItem("themeMode") ?? localStorage.getItem("theme");
  if (stored === "auto" || stored === "dark" || stored === "bright") return stored;
  if (stored === "light") return "bright";
  return "dark";
})();

const resolveTheme = (mode: string) => {
  if (mode === "auto") return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  return mode === "bright" ? "light" : "dark";
};

const initialRoute = parseRoute(window.location.pathname);

function App() {
  const [user, setUser] = useState<any>(null);
  const [setupRequired, setSetupRequired] = useState(boot?.setupRequired ?? false);
  const [booted, setBooted] = useState(Boolean(boot));
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [monitorsLoaded, setMonitorsLoaded] = useState(false);
  const [stats, setStats] = useState<any>({});
  const [channels, setChannels] = useState<any[]>([]);
  const [alerting, setAlerting] = useState<any>(null);
  const [smtp, setSmtp] = useState<any>(null);
  const [retention, setRetention] = useState<any>(null);
  const [routes, setRoutes] = useState<any[]>([]);
  const [personalAlerts, setPersonalAlerts] = useState<UserAlertSettings | null>(null);
  const [ctWatch, setCtWatch] = useState<any>(null);
  const [subscriptions, setSubscriptions] = useState<StatusSubscription[]>([]);
  const [tenants, setTenants] = useState<TenantMembership[]>([]);
  const [tenantMembers, setTenantMembers] = useState<any[]>([]);
  const [tenantInvites, setTenantInvites] = useState<TenantInvite[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [teamMembers, setTeamMembers] = useState<TeamMembership[]>([]);
  const [tenantId, setTenantId] = useState(localStorage.getItem("tenantId") ?? "");
  const [teamId, setTeamId] = useState(localStorage.getItem("teamId") ?? "");
  const [users, setUsers] = useState<any[]>([]);
  const [platformSettings, setPlatformSettings] = useState<any>({ publicRegistrationEnabled: true });
  const [impersonator, setImpersonator] = useState<any>(null);
  const [version, setVersion] = useState("");
  const [selected, setSelected] = useState<string | null>(() => initialRoute.selected);
  const [results, setResults] = useState<CheckResult[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [editing, setEditing] = useState<Monitor | null | "new">(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(initialRoute.page);
  const [themeMode, setThemeMode] = useState(initialThemeMode);
  const [resolvedTheme, setResolvedTheme] = useState(resolveTheme(initialThemeMode));
  const [liveRefreshKey, setLiveRefreshKey] = useState(0);
  const [toast, setToast] = useState("");
  const [publicConfig, setPublicConfig] = useState({
    frontPageEnabled: boot?.frontPageEnabled ?? true,
    publicRegistrationEnabled: boot?.publicRegistrationEnabled ?? true
  });
  const [inviteToken] = useState(() => new URLSearchParams(window.location.search).get("invite"));
  const [authMode, setAuthMode] = useState<"front" | "login" | "register">(() => {
    if (inviteToken) return "register";
    if (boot?.setupRequired) return "login";
    if (initialRoute.view === "app") return "login";
    return initialRoute.view === "front" ? "front" : initialRoute.view;
  });

  useEffect(() => {
    const apply = () => {
      const next = resolveTheme(themeMode);
      setResolvedTheme(next);
      document.documentElement.dataset.theme = next;
      document.documentElement.dataset.bsTheme = next;
      document.documentElement.dataset.themeMode = themeMode;
    };
    apply();
    localStorage.setItem("themeMode", themeMode);
    localStorage.setItem("theme", themeMode === "bright" ? "light" : themeMode);
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [themeMode]);
  useEffect(() => {
    api.request<any>("/auth/config")
      .then((status) => {
        setPublicConfig({
          frontPageEnabled: Boolean(status.frontPageEnabled),
          publicRegistrationEnabled: Boolean(status.publicRegistrationEnabled)
        });
        setSetupRequired(status.setupRequired);
        if (status.setupRequired) {
          setAuthMode("login");
          return null;
        }
        return api.request<any>("/auth/me").then((r) => { api.setCsrf(r.csrfToken); applyTenants(r.tenants ?? []); setUser(r.user); setImpersonator(r.impersonator ?? null); });
      })
      .catch(() => setUser(null))
      .finally(() => setBooted(true));
  }, []);
  useEffect(() => { if (user && tenantId) void refresh(); }, [user, tenantId]);
  useEffect(() => { if (selected) void loadMonitorData(selected); }, [selected]);
  useEffect(() => applyStatusFavicon(stats), [stats]);

  /* The tab names the page you are on while you work, and carries the product
     line while signed out — where it is also what a search result shows. */
  useEffect(() => {
    // The public page is German; the application keeps its English titles.
    const marketing = "crt.watch — Zertifikate und Dienste überwachen";
    if (!user) {
      document.title = marketing;
      return;
    }
    const name = (selected && monitors.find((item: Monitor) => item.id === selected)?.name) || pageTitles[page] || "Dashboard";
    document.title = `${name} · crt.watch`;
  }, [user, page, selected, monitors]);
  useEffect(() => {
    const onPopState = () => {
      const route = parseRoute(window.location.pathname);
      setPage(route.page);
      setSelected(route.selected);
      if (!route.selected) {
        setResults([]);
        setIncidents([]);
      }
      if (route.view !== "app") setAuthMode(route.view === "front" ? "front" : route.view);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  /* A signed-in visitor belongs under /app, a signed-out one at the root. The
     server redirects too; this keeps the address honest after a login or
     logout that happened without a page load. */
  useEffect(() => {
    if (!booted) return;
    const route = parseRoute(window.location.pathname);
    if (user && route.view !== "app") window.history.replaceState(null, "", pathForPage(page, selected));
    if (!user && route.view === "app") window.history.replaceState(null, "", pathForView(authMode));
  }, [booted, user]);
  const refresh = async () => {
    const [monitorData, statusData, channelData] = await Promise.all([
      api.request<Monitor[]>("/monitors"),
      api.request<any>("/status"),
      api.request<any[]>("/notification-channels")
    ]);
    const [alertingData, smtpData, retentionData, routesData, ctWatchData, subscriptionData] = await Promise.all([
      api.request<any>("/settings/alerting"),
      api.request<any>("/settings/smtp"),
      api.request<any>("/settings/retention"),
      api.request<any[]>("/notification-routes"),
      api.request<any>("/settings/ct-watch"),
      api.request<StatusSubscription[]>("/subscriptions")
    ]);
    setMonitors(monitorData);
    setMonitorsLoaded(true);
    setStats(statusData);
    setChannels(channelData);
    setAlerting(alertingData);
    setSmtp(smtpData);
    setRetention(retentionData);
    setRoutes(routesData);
    setCtWatch(ctWatchData);
    setSubscriptions(subscriptionData);
    setPersonalAlerts(await api.request<UserAlertSettings>("/me/alert-settings"));
    setVersion((await api.request<any>("/version")).version);
    setTenants(await api.request<TenantMembership[]>("/tenants"));
    await loadTenantMembers();
    if (user?.role === "super_admin" && !impersonator) {
      const [userData, platformData] = await Promise.all([api.request<any[]>("/users"), api.request<any>("/platform-settings")]);
      setUsers(userData);
      setPlatformSettings(platformData);
    }
  };

  const refreshOverview = async () => {
    const [monitorData, statusData] = await Promise.all([
      api.request<Monitor[]>("/monitors"),
      api.request<any>("/status")
    ]);
    setMonitors(monitorData);
    setStats(statusData);
  };

  const applyTenants = (items: TenantMembership[]) => {
    setTenants(items);
    const existing = localStorage.getItem("tenantId");
    const selected = items.find((item) => item.tenantId === existing)?.tenantId ?? items[0]?.tenantId ?? "";
    if (selected) {
      api.setTenant(selected);
      setTenantId(selected);
    }
  };

  const switchTenant = (nextTenantId: string) => {
    api.setTenant(nextTenantId);
    setTenantId(nextTenantId);
    localStorage.removeItem("teamId");
    setTeamId("");
    navigate("dashboard");
  };

  const switchTeam = async (nextTeamId: string) => {
    api.setTeam(nextTeamId);
    setTeamId(nextTeamId);
    const id = localStorage.getItem("tenantId");
    if (id && nextTeamId) {
      try {
        setTeamMembers(await api.request<TeamMembership[]>(`/tenants/${id}/teams/${nextTeamId}/members`));
      } catch {
        setTeamMembers([]);
      }
    }
    await refreshOverview();
  };

  const loadTenantMembers = async () => {
    const id = localStorage.getItem("tenantId");
    if (!id) {
      setTenantMembers([]);
      return setTenantInvites([]);
    }
    try {
      const [members, invites] = await Promise.all([
        api.request<any[]>(`/tenants/${id}/members`),
        api.request<TenantInvite[]>(`/tenants/${id}/invites`)
      ]);
      const teamData = await api.request<Team[]>(`/tenants/${id}/teams`);
      setTenantMembers(members);
      setTenantInvites(invites);
      setTeams(teamData);
      const existingTeam = localStorage.getItem("teamId");
      const selectedTeam = teamData.find((item) => item.id === existingTeam)?.id ?? teamData[0]?.id ?? "";
      if (selectedTeam) {
        api.setTeam(selectedTeam);
        setTeamId(selectedTeam);
        setTeamMembers(await api.request<TeamMembership[]>(`/tenants/${id}/teams/${selectedTeam}/members`));
      } else {
        setTeamMembers([]);
      }
    } catch {
      setTenantMembers([]);
      setTenantInvites([]);
      setTeams([]);
      setTeamMembers([]);
    }
  };

  const loadMonitorData = async (id: string) => {
    const [resultData, incidentData] = await Promise.all([
      api.request<CheckResult[]>(`/monitors/${id}/results`),
      api.request<Incident[]>(`/monitors/${id}/incidents`)
    ]);
    setResults(resultData);
    setIncidents(incidentData);
  };

  useLiveRefresh({
    active: Boolean(user && tenantId),
    paused: Boolean(editing),
    page,
    selected,
    refresh,
    refreshOverview,
    loadMonitorData,
    onTick: () => setLiveRefreshKey((current) => current + 1)
  });

  const saveMonitor = async (data: any) => {
    const path = editing && editing !== "new" ? `/monitors/${editing.id}` : "/monitors";
    const method = editing && editing !== "new" ? "PUT" : "POST";
    await api.request(path, { method, body: JSON.stringify(data) });
    setEditing(null);
    await refresh();
  };
  const saveAndCheck = async (data: any) => {
    const created = await api.request<Monitor>(editing && editing !== "new" ? `/monitors/${editing.id}` : "/monitors", { method: editing && editing !== "new" ? "PUT" : "POST", body: JSON.stringify(data) });
    await checkNow(created.id);
    setEditing(null);
  };
  const checkNow = async (id: string) => {
    setToast("Check started");
    await api.request(`/monitors/${id}/check`, { method: "POST", body: "{}" });
    await refresh();
    if (selected === id) await loadMonitorData(id);
    setToast("Check completed");
  };
  const deleteMonitor = async (id: string) => {
    await api.request(`/monitors/${id}`, { method: "DELETE" });
    navigate("dashboard");
    await refresh();
    setToast("Monitor deleted");
  };
  const cloneMonitor = async (id: string) => {
    const cloned = await api.request<Monitor>(`/monitors/${id}/clone`, { method: "POST", body: "{}" });
    await refresh();
    navigate("dashboard", cloned.id);
    setToast("Monitor cloned as paused");
  };
  const setMonitorEnabled = async (monitor: Monitor, enabled: boolean) => {
    await api.request(`/monitors/${monitor.id}`, { method: "PUT", body: JSON.stringify({ ...monitor, enabled }) });
    await refresh();
    if (selected === monitor.id) await loadMonitorData(monitor.id);
    setToast(enabled ? "Monitor resumed" : "Monitor paused");
  };
  const logout = async () => {
    await api.request("/auth/logout", { method: "POST", body: "{}" });
    api.setCsrf("");
    setUser(null);
    setImpersonator(null);
    setMonitors([]);
    setStats({});
    setPage("dashboard");
    setSelected(null);
    const mode = publicConfig.frontPageEnabled ? "front" : "login";
    setAuthMode(mode);
    window.history.replaceState(null, "", pathForView(mode));
  };
  const triggerSslLabs = async (monitor: Monitor) => {
    setToast("SSL Labs assessment started");
    const result = await api.request<any>("/ssl-labs/trigger", { method: "POST", body: JSON.stringify({ monitorId: monitor.id, startNewScan: true }) });
    await refreshOverview();
    if (selected === monitor.id) await loadMonitorData(monitor.id);
    setToast("SSL Labs assessment completed");
    return result;
  };
  const navigate = (nextPage: string, nextSelected: string | null = null) => {
    setPage(nextPage);
    setSelected(nextSelected);
    if (!nextSelected) {
      setResults([]);
      setIncidents([]);
    }
    window.history.pushState(null, "", pathForPage(nextPage, nextSelected));
  };
  const backToOverview = () => {
    if (parseRoute(window.location.pathname).selected) window.history.back();
    else navigate("dashboard");
  };
  const showAuth = (mode: "front" | "login" | "register") => {
    setAuthMode(mode);
    window.history.pushState(null, "", pathForView(mode));
  };
  const finishLogin = (result: any) => {
    api.setCsrf(result.csrfToken);
    applyTenants(result.tenants ?? []);
    setUser(result.user);
    setImpersonator(result.impersonator ?? null);
    setSetupRequired(false);
    window.history.replaceState(null, "", APP_PREFIX);
  };

  if (!booted) return <BootScreen />;
  if (!user && setupRequired) return <Login setupRequired registrationEnabled={false} onLogin={finishLogin} />;
  if (!user && authMode === "register") return <Register inviteToken={inviteToken} onBack={() => showAuth("login")} onLogin={finishLogin} />;
  if (!user && publicConfig.frontPageEnabled && authMode === "front") {
    return <FrontPage setupRequired={setupRequired} registrationEnabled={publicConfig.publicRegistrationEnabled} onAuth={() => showAuth("login")} onRegister={() => showAuth("register")} />;
  }
  if (!user) {
    return <Login
      setupRequired={false}
      registrationEnabled={publicConfig.publicRegistrationEnabled}
      onBack={publicConfig.frontPageEnabled ? () => showAuth("front") : undefined}
      onRegister={() => showAuth("register")}
      onLogin={finishLogin}
    />;
  }
  const selectedMonitor = monitors.find((monitor) => monitor.id === selected);

  return (
    <Layout
      page={page}
      pageTitle={selectedMonitor?.name}
      onPage={(nextPage: string) => navigate(nextPage)}
      onNew={() => setEditing("new")}
      theme={resolvedTheme}
      themeMode={themeMode}
      setThemeMode={setThemeMode}
      version={version}
      stats={stats}
      monitors={monitors}
      onSelectMonitor={(id: string) => navigate("dashboard", id)}
      tenants={tenants}
      tenantId={tenantId}
      onTenant={switchTenant}
      teams={teams}
      teamId={teamId}
      onTeam={switchTeam}
      user={user}
      impersonator={impersonator}
      onStopImpersonation={async () => finishLogin(await api.request("/auth/stop-impersonation", { method: "POST", body: "{}" }))}
      onProfile={() => navigate("profile")}
      onLogout={logout}
    >
      {toast && <div className="toast" onAnimationEnd={() => setToast("")}>{toast}</div>}
      {page === "settings" ? (
        <Settings
          channels={channels}
          alerting={alerting}
          smtp={smtp}
          retention={retention}
          routes={routes}
          personalAlerts={personalAlerts}
          ctWatch={ctWatch}
          subscriptions={subscriptions}
          theme={themeMode}
          setTheme={setThemeMode}
          onSaveChannel={async (channel: any) => { await api.request("/notification-channels", { method: "POST", body: JSON.stringify(channel) }); await refresh(); }}
          onDeleteChannel={async (id: string) => { await api.request(`/notification-channels/${id}`, { method: "DELETE" }); await refresh(); }}
          onTest={(id: string) => api.request("/notification-channels/test", { method: "POST", body: JSON.stringify({ id }) })}
          onSaveAlerting={async (data: any) => { await api.request("/settings/alerting", { method: "PUT", body: JSON.stringify(data) }); await refresh(); }}
          onSaveSmtp={async (data: any) => { await api.request("/settings/smtp", { method: "PUT", body: JSON.stringify(data) }); await refresh(); }}
          onSaveRetention={async (data: any) => { await api.request("/settings/retention", { method: "PUT", body: JSON.stringify(data) }); await refresh(); }}
          onSaveRoutes={async (data: any) => { await api.request("/notification-routes", { method: "PUT", body: JSON.stringify(data) }); await refresh(); }}
          onSavePersonalAlerts={async (data: any) => { const saved = await api.request<UserAlertSettings>("/me/alert-settings", { method: "PUT", body: JSON.stringify(data) }); setPersonalAlerts(saved); }}
          onSaveCtWatch={async (data: any) => { await api.request("/settings/ct-watch", { method: "PUT", body: JSON.stringify(data) }); await refresh(); }}
          onCheckCtWatch={async () => api.request("/ct-watch/check", { method: "POST", body: "{}" })}
          onDeleteSubscription={async (id: string) => { await api.request(`/subscriptions/${id}`, { method: "DELETE" }); await refresh(); }}
        />
      ) : page === "import" ? (
        <BulkImport
          onImport={async (text) => { const result = await api.request("/monitors/bulk", { method: "POST", body: JSON.stringify({ text }) }); await refresh(); return result; }}
          onDiscover={async (domain: string) => api.request("/discover", { method: "POST", body: JSON.stringify({ domain }) })}
          onAcceptDiscovery={async (items: any[]) => { const result = await api.request("/discovery/import", { method: "POST", body: JSON.stringify({ monitors: items }) }); await refresh(); return result; }}
          onRestore={async (backup: any) => { const result = await api.request("/export/restore", { method: "POST", body: JSON.stringify(backup) }); await refresh(); return result; }}
        />
      ) : page === "users" ? (
        <UsersPage
          users={users}
          currentUser={user}
          platformSettings={platformSettings}
          onSavePlatformSettings={async (data: any) => { setPlatformSettings(await api.request("/platform-settings", { method: "PUT", body: JSON.stringify(data) })); await refresh(); }}
          onCreate={async (data: any) => { await api.request("/users", { method: "POST", body: JSON.stringify(data) }); await refresh(); }}
          onUpdate={async (id: string, data: any) => { await api.request(`/users/${id}`, { method: "PUT", body: JSON.stringify(data) }); await refresh(); }}
          onDelete={async (id: string) => { await api.request(`/users/${id}`, { method: "DELETE" }); await refresh(); }}
          onImpersonate={async (id: string) => finishLogin(await api.request(`/users/${id}/impersonate`, { method: "POST", body: "{}" }))}
        />
      ) : page === "tenants" ? (
        <TenantsPage
          tenants={tenants}
          members={tenantMembers}
          invites={tenantInvites}
          teams={teams}
          teamMembers={teamMembers}
          onCreateTenant={async (name) => { const created = await api.request<any>("/tenants", { method: "POST", body: JSON.stringify({ name }) }); api.setTenant(created.tenantId); setTenantId(created.tenantId); await refresh(); }}
          onInviteMember={async (input) => { const result = await api.request<any>(`/tenants/${tenantId}/invites`, { method: "POST", body: JSON.stringify(input) }); await loadTenantMembers(); return result.invite ?? null; }}
          onUpdateMember={async (userId, data) => { await api.request(`/tenants/${tenantId}/members/${userId}`, { method: "PUT", body: JSON.stringify(data) }); await loadTenantMembers(); }}
          onRemoveMember={async (userId) => { await api.request(`/tenants/${tenantId}/members/${userId}`, { method: "DELETE" }); await loadTenantMembers(); }}
          onDeleteInvite={async (inviteId) => { await api.request(`/tenants/${tenantId}/invites/${inviteId}`, { method: "DELETE" }); await loadTenantMembers(); }}
          onCreateTeam={async (team) => { await api.request(`/tenants/${tenantId}/teams`, { method: "POST", body: JSON.stringify(team) }); await loadTenantMembers(); }}
          onUpdateTeam={async (id, team) => { await api.request(`/tenants/${tenantId}/teams/${id}`, { method: "PUT", body: JSON.stringify(team) }); await loadTenantMembers(); }}
          onArchiveTeam={async (id) => { await api.request(`/tenants/${tenantId}/teams/${id}`, { method: "DELETE" }); await loadTenantMembers(); }}
          onAddTeamMember={async (teamId, email, role) => { await api.request(`/tenants/${tenantId}/teams/${teamId}/members`, { method: "POST", body: JSON.stringify({ email, role }) }); await loadTenantMembers(); }}
          onUpdateTeamMember={async (teamId, userId, data) => { await api.request(`/tenants/${tenantId}/teams/${teamId}/members/${userId}`, { method: "PUT", body: JSON.stringify(data) }); await loadTenantMembers(); }}
          onRemoveTeamMember={async (teamId, userId) => { await api.request(`/tenants/${tenantId}/teams/${teamId}/members/${userId}`, { method: "DELETE" }); await loadTenantMembers(); }}
        />
      ) : page === "applications" ? (
        <Applications monitors={monitors} onSelect={(id) => navigate("dashboard", id)} />
      ) : page === "profile" ? (
        <Profile
          user={user}
          tenants={tenants}
          onChangePassword={(data: any) => api.request("/auth/change-password", { method: "POST", body: JSON.stringify(data) })}
          onLogout={logout}
          onMfaChanged={async () => setUser((await api.request<any>("/auth/me")).user)}
        />
      ) : page === "operations" ? (
        <Operations liveRefreshKey={liveRefreshKey} />
      ) : page === "reports" ? (
        <Reports liveRefreshKey={liveRefreshKey} />
      ) : selectedMonitor ? (
        <MonitorDetail
          monitor={selectedMonitor}
          results={results}
          incidents={incidents}
          onBack={backToOverview}
          onEdit={() => setEditing(selectedMonitor)}
          onCheck={() => checkNow(selectedMonitor.id)}
          onClone={() => cloneMonitor(selectedMonitor.id)}
          onToggleEnabled={() => setMonitorEnabled(selectedMonitor, !selectedMonitor.enabled)}
          onDelete={() => deleteMonitor(selectedMonitor.id)}
          onSslLabs={() => triggerSslLabs(selectedMonitor)}
          onAck={async (id: string, assignee: string, comment: string) => { await api.request(`/incidents/${id}/ack`, { method: "POST", body: JSON.stringify({ assignee, comment }) }); await loadMonitorData(selectedMonitor.id); }}
          onNote={async (id: string, text: string) => { await api.request(`/incidents/${id}/notes`, { method: "POST", body: JSON.stringify({ text }) }); await loadMonitorData(selectedMonitor.id); }}
        />
      ) : (
        <Dashboard monitors={monitors} loaded={monitorsLoaded} stats={stats} query={query} setQuery={setQuery} onSelect={(id: string) => navigate("dashboard", id)} onCheck={checkNow} onClone={cloneMonitor} onToggleEnabled={(monitor: Monitor) => setMonitorEnabled(monitor, !monitor.enabled)} onNew={() => setEditing("new")} />
      )}
      {editing && <MonitorForm channels={channels} monitor={editing === "new" ? null : editing} onCancel={() => setEditing(null)} onSave={saveMonitor} onSaveAndCheck={saveAndCheck} />}
    </Layout>
  );
}

const container = document.getElementById("root")!;
const tree = <React.StrictMode><App /></React.StrictMode>;
if (boot && container.firstElementChild) hydrateRoot(container, tree);
else createRoot(container).render(tree);

import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api/client";
import { humanize } from "../utils/labels";

export function Profile({ user, tenants, passwordMinLength, onChangePassword, onLogout, onMfaChanged }: any) {
  const [form, setForm] = useState({ currentPassword: "", newPassword: "", confirmPassword: "" });
  const [message, setMessage] = useState("");
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setMessage("");
    if (form.newPassword !== form.confirmPassword) return setMessage("New passwords do not match.");
    try {
      await onChangePassword({ currentPassword: form.currentPassword, newPassword: form.newPassword });
      setForm({ currentPassword: "", newPassword: "", confirmPassword: "" });
      setMessage("Password changed.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Password change failed.");
    }
  };

  return (
    <section className="content">
      <div className="grid two">
        <div className="panel">
          <h3>Account</h3>
          <Info label="Email" value={user?.email} />
          <Info label="Platform role" value={humanize(user?.role)} />
          <Info label="Organizations" value={(tenants ?? []).map((item: any) => `${item.tenant.name} (${humanize(item.role)})`).join(", ")} />
          <div className="actions">
            <button className="btn btn-outline-secondary" type="button" onClick={onLogout}>Log out</button>
          </div>
        </div>
        <form className="panel" onSubmit={submit}>
          <h3>Change password</h3>
          <label>Current password<input type="password" autoComplete="current-password" value={form.currentPassword} onChange={(event) => setForm({ ...form, currentPassword: event.target.value })} required /></label>
          <label>New password<input type="password" autoComplete="new-password" minLength={passwordMinLength} value={form.newPassword} onChange={(event) => setForm({ ...form, newPassword: event.target.value })} required /></label>
          <label>Repeat new password<input type="password" autoComplete="new-password" minLength={passwordMinLength} value={form.confirmPassword} onChange={(event) => setForm({ ...form, confirmPassword: event.target.value })} required /></label>
          {message && <p className={message === "Password changed." ? "success" : "error"}>{message}</p>}
          <button className="btn btn-primary" type="submit">Save password</button>
        </form>
      </div>
      <MfaPanel user={user} onMfaChanged={onMfaChanged} />
    </section>
  );
}

function MfaPanel({ user, onMfaChanged }: any) {
  const [setup, setSetup] = useState<{ secret: string; otpauthUrl: string } | null>(null);
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [disablePassword, setDisablePassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const startSetup = async () => {
    setError(""); setMessage(""); setBackupCodes(null);
    const result = await api.request<any>("/auth/mfa/setup", { method: "POST", body: "{}" });
    setSetup(result);
  };

  const confirmSetup = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    try {
      const result = await api.request<any>("/auth/mfa/enable", { method: "POST", body: JSON.stringify({ code }) });
      setBackupCodes(result.backupCodes);
      setSetup(null);
      setCode("");
      onMfaChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
    }
  };

  const disable = async (event: FormEvent) => {
    event.preventDefault();
    setError(""); setMessage("");
    try {
      await api.request("/auth/mfa/disable", { method: "POST", body: JSON.stringify({ password: disablePassword }) });
      setDisablePassword("");
      setMessage("Two-factor authentication disabled.");
      onMfaChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not disable two-factor authentication.");
    }
  };

  return (
    <div className="panel">
      <h3>Two-factor authentication</h3>
      {backupCodes ? (
        <div className="callout callout-info">
          <strong>Two-factor authentication is enabled.</strong>
          <p>Save these backup codes somewhere safe. Each can be used once if you lose access to your authenticator app.</p>
          <pre>{backupCodes.join("\n")}</pre>
        </div>
      ) : user?.mfaEnabled ? (
        <form onSubmit={disable}>
          <p className="muted">Two-factor authentication is currently enabled for your account.</p>
          <label>Current password<input type="password" autoComplete="current-password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} required /></label>
          {error && <p className="error">{error}</p>}
          {message && <p className="form-note success">{message}</p>}
          <button className="btn btn-outline-danger" type="submit">Disable two-factor authentication</button>
        </form>
      ) : setup ? (
        <form onSubmit={confirmSetup}>
          <p className="muted">Scan this key with your authenticator app (Google Authenticator, Authy, 1Password, ...), or enter it manually.</p>
          <label>Secret key<input readOnly value={setup.secret} onFocus={(e) => e.currentTarget.select()} /></label>
          <label>Setup URI<input readOnly value={setup.otpauthUrl} onFocus={(e) => e.currentTarget.select()} /></label>
          <label>6-digit code<input autoFocus value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" required /></label>
          {error && <p className="error">{error}</p>}
          <div className="actions">
            <button className="btn btn-primary" type="submit">Confirm and enable</button>
            <button className="btn btn-outline-secondary" type="button" onClick={() => setSetup(null)}>Cancel</button>
          </div>
        </form>
      ) : (
        <>
          <p className="muted">Add an authenticator app as a second sign-in factor.</p>
          <button className="btn btn-primary" type="button" onClick={startSetup}>Enable two-factor authentication</button>
        </>
      )}
    </div>
  );
}

function Info({ label, value }: { label: string; value?: string | null }) {
  return <div className="info"><span>{label}</span><strong>{value || "-"}</strong></div>;
}

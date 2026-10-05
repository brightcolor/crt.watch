import { useState } from "react";
import type { FormEvent } from "react";
import { formatDate } from "../utils/date";

export function UsersPage({ users, currentUser, passwordMinLength, platformSettings, onSavePlatformSettings, onCreate, onUpdate, onDelete, onImpersonate }: any) {
  const [form, setForm] = useState({ email: "", password: "", role: "viewer", tenantRole: "viewer" });
  const [settings, setSettings] = useState(platformSettings ?? { publicRegistrationEnabled: true });
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setMessage("");
    const email = form.email.trim();
    if (!email) return setError("Email is required.");
    if (passwordMinLength && form.password.length < passwordMinLength) return setError(`Password must be at least ${passwordMinLength} characters long.`);
    setSaving(true);
    try {
      await onCreate({ ...form, email });
      setForm({ email: "", password: "", role: "viewer", tenantRole: "viewer" });
      setMessage("User created.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "User could not be created.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="content">
      <div className="flow">
        <div className="panel">
          <h3>Registration</h3>
          <p className="muted">This controls public self-signup. Invite links still work when public registration is disabled.</p>
          <label><input type="checkbox" checked={settings.publicRegistrationEnabled} onChange={(event) => setSettings({ ...settings, publicRegistrationEnabled: event.target.checked })} /> Allow public organization registration</label>
          <button className="btn btn-primary" onClick={async () => { await onSavePlatformSettings(settings); setMessage("Registration settings saved."); }}>Save registration settings</button>
        </div>
        <form className="panel" onSubmit={submit}>
          <h3>Create user</h3>
          <p className="muted">Super admins manage the instance. Organization rights are assigned per tenant.</p>
          <label>Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /></label>
          <label>Password<input type="password" minLength={passwordMinLength} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required autoComplete="new-password" /></label>
          <label>Platform role<select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{platformRoleOptions()}</select></label>
          <label>Current organization role<select value={form.tenantRole} onChange={(e) => setForm({ ...form, tenantRole: e.target.value })}>{tenantRoleOptions()}</select></label>
          {error && <p className="error">{error}</p>}
          {message && <p className="form-note success">{message}</p>}
          <button className="btn btn-primary" type="submit" disabled={saving}>{saving ? "Creating..." : "Create user"}</button>
        </form>
      </div>
      <div className="panel">
        <h3>Platform users</h3>
        <p className="muted">Use impersonation for support and troubleshooting only. While impersonating, the header shows a button that returns you to your own account.</p>
        {users.map((user: any) => <UserRow user={user} currentUser={currentUser} passwordMinLength={passwordMinLength} onUpdate={onUpdate} onDelete={onDelete} onImpersonate={onImpersonate} key={user.id} />)}
        {!users.length && <span className="muted">No users found.</span>}
      </div>
    </section>
  );
}

function UserRow({ user, currentUser, passwordMinLength, onUpdate, onDelete, onImpersonate }: any) {
  const [role, setRole] = useState(user.role);
  const [password, setPassword] = useState("");
  const self = currentUser?.id === user.id;
  return (
    <div className="member-row">
      <div>
        <strong>{user.email}</strong>
        <span>Created {formatDate(user.createdAt)}</span>
      </div>
      <label>Platform role<select value={role} onChange={(event) => setRole(event.target.value)}>{platformRoleOptions()}</select></label>
      <label>New password<input type="password" minLength={passwordMinLength} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Leave empty to keep" /></label>
      <div className="actions end">
        <button className="btn btn-primary" onClick={() => { onUpdate(user.id, { role, password }); setPassword(""); }}>Save</button>
        <button className="btn btn-outline-secondary" disabled={self} onClick={() => onImpersonate(user.id)}>Impersonate</button>
        <button className="btn btn-outline-danger" disabled={self} onClick={() => onDelete(user.id)}>Delete</button>
      </div>
    </div>
  );
}

const platformRoleOptions = () => <>
  <option value="viewer">Viewer</option>
  <option value="admin">Admin</option>
  <option value="super_admin">Super admin</option>
</>;

const tenantRoleOptions = () => <>
  <option value="viewer">Viewer</option>
  <option value="member">Member</option>
  <option value="admin">Admin</option>
  <option value="owner">Owner</option>
</>;

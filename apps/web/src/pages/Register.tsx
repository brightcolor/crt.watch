import { useState } from "react";
import { api } from "../api/client";
import { BrandMark } from "../components/BrandMark";

export function Register({ inviteToken, passwordMinLength, onLogin, onBack }: { inviteToken?: string | null; passwordMinLength?: number; onLogin: (result: any) => void; onBack: () => void }) {
  const [form, setForm] = useState({ email: "", password: "", confirm: "", organizationName: "" });
  const [error, setError] = useState("");
  const invited = Boolean(inviteToken);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    if (form.password !== form.confirm) return setError("Passwords do not match.");
    try {
      const result = await api.request<any>("/auth/register", {
        method: "POST",
        body: JSON.stringify({
          email: form.email,
          password: form.password,
          organizationName: invited ? undefined : form.organizationName,
          inviteToken: inviteToken || undefined
        })
      });
      api.setCsrf(result.csrfToken);
      onLogin(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed.");
    }
  };

  return (
    <main className="login">
      <form onSubmit={submit} className="login-panel">
        <span className="brand-line"><BrandMark size={18} /> crt.watch</span>
        <h1>{invited ? "Join organization" : "Create organization"}</h1>
        <p className="muted">
          {invited ? "Create your account to accept this organization invitation." : "Create a user account and an isolated organization."}
        </p>
        <label>Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /></label>
        {!invited && <label>Organization<input value={form.organizationName} onChange={(e) => setForm({ ...form, organizationName: e.target.value })} required /></label>}
        <label>Password<input type="password" autoComplete="new-password" minLength={passwordMinLength} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required /></label>
        <label>Confirm password<input type="password" autoComplete="new-password" minLength={passwordMinLength} value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} required /></label>
        {error && <p className="error">{error}</p>}
        <button className="btn btn-primary" type="submit">{invited ? "Accept invite" : "Create organization"}</button>
        <button className="btn btn-outline-secondary" type="button" onClick={onBack}>Back to sign in</button>
      </form>
    </main>
  );
}

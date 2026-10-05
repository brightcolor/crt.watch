import { useState } from "react";
import { api } from "../api/client";
import { BrandMark } from "../components/BrandMark";

export function Login({ setupRequired, registrationEnabled, passwordMinLength, setupCodeCommand, onLogin, onBack, onRegister }: {
  setupRequired: boolean;
  registrationEnabled?: boolean;
  passwordMinLength?: number;
  /** The command that prints the setup code on the server, from /auth/config. */
  setupCodeCommand?: string;
  onLogin: (result: any) => void;
  onBack?: () => void;
  onRegister?: () => void;
}) {
  const [email, setEmail] = useState("admin@example.com");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [organizationName, setOrganizationName] = useState("Default organization");
  const [setupCode, setSetupCode] = useState("");
  const [error, setError] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [mfaCode, setMfaCode] = useState("");

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    if (setupRequired && password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    try {
      const body = setupRequired ? { email, password, organizationName, setupCode } : { email, password };
      const result = await api.request<any>(setupRequired ? "/auth/setup" : "/auth/login", { method: "POST", body: JSON.stringify(body) });
      if (result.mfaRequired) {
        setMfaToken(result.mfaToken);
        return;
      }
      api.setCsrf(result.csrfToken);
      onLogin(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed.");
    }
  };

  const submitMfa = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    try {
      const result = await api.request<any>("/auth/mfa/verify-login", { method: "POST", body: JSON.stringify({ mfaToken, code: mfaCode }) });
      api.setCsrf(result.csrfToken);
      onLogin(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
    }
  };

  if (mfaToken) {
    return (
      <main className="login">
        <form onSubmit={submitMfa} className="login-panel">
          <span className="brand-line"><BrandMark size={18} /> crt.watch</span>
          <h1>Two-factor authentication</h1>
          <p className="muted">Enter the 6-digit code from your authenticator app, or a backup code.</p>
          <label>Code<input autoFocus value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="123456" /></label>
          {error && <p className="error">{error}</p>}
          <button className="btn btn-primary" type="submit">Verify</button>
          <button className="btn btn-outline-secondary" type="button" onClick={() => { setMfaToken(""); setMfaCode(""); setError(""); }}>Back to sign in</button>
        </form>
      </main>
    );
  }

  return (
    <main className="login">
      {/* Two halves, as every workbench sign-in in the house: the onyx side
          greets, the card takes the credentials. */}
      <aside className="login-aside">
        <span className="brand-line"><BrandMark size={22} /> crt.watch</span>
        <p className="login-greeting">Moin.</p>
        <p className="login-claim">Certificate and service monitoring</p>
      </aside>
      <form onSubmit={submit} className="login-panel">
        <span className="brand-line"><BrandMark size={18} /> crt.watch</span>
        <h1>{setupRequired ? "Create admin" : "Sign in"}</h1>
        {setupRequired && <p className="muted">Create the first administrator account for this crt.watch instance. The setup code is in the server log of the current start{setupCodeCommand ? <>, or print it on the server with <code>{setupCodeCommand}</code></> : null}.</p>}
        {setupRequired && <label>Setup code<input value={setupCode} onChange={(e) => setSetupCode(e.target.value)} autoComplete="off" spellCheck={false} placeholder="XXXX-XXXX-XXXX-XXXX" required /></label>}
        <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        {setupRequired && <label>Organization<input value={organizationName} onChange={(e) => setOrganizationName(e.target.value)} /></label>}
        <label>Password<input type="password" autoComplete={setupRequired ? "new-password" : "current-password"} minLength={setupRequired ? passwordMinLength : undefined} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {setupRequired && passwordMinLength && <p className="form-note">At least {passwordMinLength} characters.</p>}
        {setupRequired && <label>Confirm password<input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></label>}
        {error && <p className="error">{error}</p>}
        <button className="btn btn-primary" type="submit">{setupRequired ? "Create admin" : "Sign in"}</button>
        {!setupRequired && registrationEnabled && onRegister && <button className="btn btn-outline-secondary" type="button" onClick={onRegister}>Create organization</button>}
        {onBack && <button className="btn btn-outline-secondary" type="button" onClick={onBack}>Back to overview</button>}
      </form>
    </main>
  );
}

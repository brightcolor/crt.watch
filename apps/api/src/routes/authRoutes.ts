import { createHash } from "node:crypto";
import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { clearSessionCookie, publicUser, requireAuth, setSessionCookie } from "../auth/auth.js";
import { authenticateLocal, createUserSession } from "../auth/passport.js";
import { passwordRule } from "../auth/passwords.js";
import { clearSetupCode, setupCodeCommand, setupCodeMatches, setupRequired } from "../auth/setup.js";
import { createMfaChallenge, randomToken, verifyMfaChallenge } from "../auth/tokens.js";
import { env } from "../config/env.js";
import { authLimiter, mfaAccountLimiter } from "../security/rateLimits.js";
import { appSettings, auditLogs, teams, tenantInvites, tenants, users } from "../storage/repositories.js";
import { decryptSecret, encryptSecret } from "../utils/secrets.js";
import { buildOtpAuthUrl, generateTotpSecret, verifyTotp } from "../utils/totp.js";

export const authRoutes = Router();

const invalidCode = "The code is not valid. Enter the current 6-digit code from your authenticator app or an unused backup code.";
const setupClosed = "The setup of this crt.watch instance is complete. Sign in instead, or ask an administrator for an account.";
const wrongSetupCode = `The setup code is not valid. Use the code from the server log of the current start, or print it on the server with: ${setupCodeCommand}`;

authRoutes.get("/setup-status", (_req, res) => {
  res.json({ setupRequired: setupRequired() });
});

authRoutes.get("/config", (_req, res) => {
  const pending = setupRequired();
  res.json({
    setupRequired: pending,
    frontPageEnabled: env.frontPageEnabled,
    publicRegistrationEnabled: publicRegistrationEnabled(),
    passwordMinLength: env.passwordMinLength,
    // Where the operator finds the setup code; the code itself never leaves the server here.
    ...(pending ? { setupCodeCommand } : {})
  });
});

/* Creates the first platform administrator. It needs the setup code from the
   server log or the setup-code command and is closed while an administrator
   exists; failed attempts count against the sign-in limit. */
authRoutes.post("/setup", authLimiter, async (req, res) => {
  if (!setupRequired()) return res.status(404).json({ error: setupClosed });
  const body = setupSchema().safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: body.error.issues[0]?.message ?? "Enter an email address, a password and the setup code." });
  if (!setupCodeMatches(body.data.setupCode)) return res.status(403).json({ error: wrongSetupCode });
  const passwordHash = await bcrypt.hash(body.data.password, 12);
  // Checked again after the await, so two requests with the right code cannot both create an administrator.
  if (!setupRequired()) return res.status(404).json({ error: setupClosed });
  if (!setupCodeMatches(body.data.setupCode)) return res.status(403).json({ error: wrongSetupCode });
  if (users.findByEmail(body.data.email)) return res.status(409).json({ error: "An account with this email address already exists. Use a different address for the administrator." });
  const user = users.create(body.data.email, passwordHash, "super_admin");
  const tenant = tenants.create(body.data.organizationName || "Default organization", user.id);
  clearSetupCode();
  auditLogs.record({ tenantId: tenant.id, actorUserId: user.id, targetUserId: user.id, action: "setup.completed", metadata: { email: user.email, role: user.role } });
  console.log("First-run setup completed: the first administrator account exists, and the setup is closed.");
  const session = createUserSession(user.id);
  setSessionCookie(res, session.token);
  res.status(201).json(withMemberships(publicUser(user), session.csrfToken, user.id));
});

authRoutes.post("/register", authLimiter, async (req, res) => {
  if (setupRequired()) return res.status(409).json({ error: "This crt.watch instance is not set up yet. Registration opens once the operator has created the first administrator account." });
  const parsed = registerSchema().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid registration payload." });

  const invite = parsed.data.inviteToken ? tenantInvites.findByToken(parsed.data.inviteToken) : null;
  if (parsed.data.inviteToken && !invite) return res.status(404).json({ error: "Invitation is invalid or expired." });
  if (!invite && !publicRegistrationEnabled()) return res.status(403).json({ error: "Public registration is disabled." });
  if (invite && invite.email !== parsed.data.email) return res.status(409).json({ error: "This invitation was issued for a different email address." });
  if (!invite && !parsed.data.organizationName) return res.status(400).json({ error: "Organization name is required." });
  if (users.findByEmail(parsed.data.email)) return res.status(409).json({ error: "A user with this email already exists. Sign in instead." });
  if (invite && !organizationHasRoom(invite.tenantId)) return res.status(402).json({ error: "Organization user limit reached." });

  // A registered account never gets a platform role; the first administrator comes from the setup.
  const user = users.create(parsed.data.email, await bcrypt.hash(parsed.data.password, 12), "viewer");
  if (invite) tenantInvites.accept(invite, user.id);
  else tenants.create(parsed.data.organizationName!, user.id);

  const session = createUserSession(user.id);
  setSessionCookie(res, session.token);
  res.status(201).json(withMemberships(publicUser(user), session.csrfToken, user.id));
});

authRoutes.post("/login", authLimiter, async (req, res) => {
  const body = z.object({ email: z.string().email(), password: z.string().min(1) }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: "Enter a valid email address and your password." });
  const user = await authenticateLocal(req);
  if (!user) return res.status(401).json({ error: "Invalid email or password." });
  if (user.mfaEnabled) return res.json({ mfaRequired: true, mfaToken: createMfaChallenge(user.id) });
  const session = createUserSession(user.id);
  setSessionCookie(res, session.token);
  res.json(withMemberships(publicUser(user), session.csrfToken, user.id));
});

authRoutes.post("/mfa/verify-login", authLimiter, mfaAccountLimiter, async (req, res) => {
  const body = z.object({ mfaToken: z.string().min(1), code: z.string().min(1) }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: "Enter the 6-digit code from your authenticator app or one of your backup codes." });
  const userId = verifyMfaChallenge(body.data.mfaToken);
  if (!userId) return res.status(401).json({ error: "The verification code has expired. Sign in again." });
  const user = users.findById(userId);
  if (!user || !user.mfaEnabled) return res.status(401).json({ error: "Two-factor authentication is not active for this account." });
  const secret = decryptSecret(users.getMfaSecret(user.id));
  const normalizedCode = body.data.code.trim();
  const valid = verifyTotp(secret, normalizedCode) || users.consumeMfaBackupCode(user.id, hashBackupCode(normalizedCode));
  if (!valid) return res.status(401).json({ error: invalidCode });
  const session = createUserSession(user.id);
  setSessionCookie(res, session.token);
  res.json(withMemberships(publicUser(user), session.csrfToken, user.id));
});

authRoutes.post("/mfa/setup", requireAuth, authLimiter, (req, res) => {
  // A new secret replaces the active one and switches the second factor off
  // until it is confirmed, so an active setup is only left through /mfa/disable,
  // which asks for the password.
  if (req.user!.mfaEnabled) {
    return res.status(409).json({ error: "Two-factor authentication is already active. To set it up again, first disable it with your current password." });
  }
  const secret = generateTotpSecret();
  users.setPendingMfaSecret(req.user!.id, encryptSecret(secret));
  res.json({ secret, otpauthUrl: buildOtpAuthUrl("crt.watch", req.user!.email, secret) });
});

authRoutes.post("/mfa/enable", requireAuth, authLimiter, (req, res) => {
  const body = z.object({ code: z.string().min(1) }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: "A verification code is required." });
  const secret = decryptSecret(users.getMfaSecret(req.user!.id));
  if (!secret || !verifyTotp(secret, body.data.code.trim())) return res.status(400).json({ error: "The code is not valid. Enter the current 6-digit code your authenticator app shows for crt.watch." });
  const backupCodes = Array.from({ length: 8 }, generateBackupCode);
  users.enableMfa(req.user!.id, backupCodes.map(hashBackupCode));
  res.json({ ok: true, backupCodes });
});

authRoutes.post("/mfa/disable", requireAuth, authLimiter, async (req, res) => {
  const body = z.object({ password: z.string().min(1) }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: "Current password is required." });
  const user = users.findById(req.user!.id);
  if (!user || !(await bcrypt.compare(body.data.password, user.passwordHash))) return res.status(401).json({ error: "Current password is incorrect." });
  users.disableMfa(user.id);
  res.json({ ok: true });
});

authRoutes.post("/logout", requireAuth, (req, res) => {
  clearSessionCookie(req, res);
  res.json({ ok: true });
});

authRoutes.post("/change-password", requireAuth, authLimiter, async (req, res) => {
  const parsed = z.object({
    currentPassword: z.string().min(1, "Enter your current password."),
    newPassword: passwordRule()
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0]?.message ?? "Invalid password payload." });
  const user = users.findById(req.user!.id);
  if (!user || !(await bcrypt.compare(parsed.data.currentPassword, user.passwordHash))) return res.status(401).json({ error: "Current password is incorrect." });
  users.update(user.id, user.role, await bcrypt.hash(parsed.data.newPassword, 12));
  res.json({ ok: true });
});

authRoutes.get("/me", requireAuth, (req, res) => {
  res.json({ ...withMemberships(publicUser(req.user!), req.csrfToken, req.user!.id), impersonator: req.impersonator ? publicUser(req.impersonator) : null });
});

authRoutes.post("/stop-impersonation", requireAuth, async (req, res) => {
  if (!req.impersonator) return res.status(409).json({ error: "No impersonation session is active." });
  clearSessionCookie(req, res);
  const impersonator = req.impersonator;
  const session = createUserSession(impersonator.id);
  setSessionCookie(res, session.token);
  res.json(withMemberships(publicUser(impersonator), session.csrfToken, impersonator.id));
});

const withMemberships = (user: ReturnType<typeof publicUser>, csrfToken: string | undefined, userId: string) => ({
  user,
  csrfToken,
  tenants: tenants.forUser(userId).map(publicMembership),
  teams: teamsForUser(userId)
});

const publicMembership = (membership: any) => ({
  tenantId: membership.tenantId,
  role: membership.role,
  tenant: membership.tenant
});

const teamsForUser = (userId: string) =>
  Object.fromEntries(tenants.forUser(userId).map((membership) => [
    membership.tenantId,
    teams.listForUser(membership.tenantId, userId, membership.role)
  ]));

const registerSchema = () => z.object({
  email: z.string().trim().email().transform((email) => email.toLowerCase()),
  password: passwordRule(),
  organizationName: z.string().trim().min(2).max(120).optional().or(z.literal("")),
  inviteToken: z.string().trim().min(8).optional().or(z.literal(""))
}).transform((value) => ({
  ...value,
  organizationName: value.organizationName || undefined,
  inviteToken: value.inviteToken || undefined
}));

const setupSchema = () => z.object({
  email: z.string().trim().email("Enter a valid email address for the administrator.").transform((email) => email.toLowerCase()),
  password: passwordRule(),
  organizationName: z.string().trim().min(2, "An organization name needs at least 2 characters.").max(120, "An organization name can have at most 120 characters.").optional().or(z.literal("")),
  setupCode: z.string({ required_error: `Enter the setup code. It is in the server log, or print it on the server with: ${setupCodeCommand}` }).trim().min(1, `Enter the setup code. It is in the server log, or print it on the server with: ${setupCodeCommand}`)
});

const organizationHasRoom = (tenantId: string) => {
  const tenant = tenants.get(tenantId);
  return !tenant || tenant.userLimit <= 0 || tenants.members(tenant.id).length < tenant.userLimit;
};

export const publicRegistrationEnabled = () =>
  env.publicRegistrationEnabled && appSettingPublicRegistration();

const generateBackupCode = () => randomToken(4).match(/.{1,4}/g)!.join("-");
const hashBackupCode = (code: string) => createHash("sha256").update(code.trim().toLowerCase()).digest("hex");

const appSettingPublicRegistration = () => {
  return appSettings.platform().publicRegistrationEnabled;
};

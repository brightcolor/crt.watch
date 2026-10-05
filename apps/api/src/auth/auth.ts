import { createHash } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { env } from "../config/env.js";
import { apiTokens, sessions, teamMemberships, teams, tenants, users } from "../storage/repositories.js";
import type { ApiToken, Team, TeamMembership, TeamRole, Tenant, TenantMembership, TenantRole, User as AppUser } from "../types.js";
import { createUserSession } from "./passport.js";
import { bearerToken, randomToken } from "./tokens.js";

declare global {
  namespace Express {
    interface User extends AppUser {}
    interface Request {
      apiToken?: ApiToken;
      csrfToken?: string;
      currentTenant?: Tenant;
      currentTeam?: Team;
      tenantRole?: TenantRole;
      teamRole?: TeamRole;
      tenantMemberships?: TenantMembership[];
      teamMemberships?: TeamMembership[];
      impersonator?: AppUser;
    }
  }
}

const cookieName = "crtwatch_session";

export const createImpersonationSession = (targetUserId: string, impersonatorUserId: string) => {
  const target = users.findById(targetUserId);
  const impersonator = users.findById(impersonatorUserId);
  if (!target || !impersonator || impersonator.role !== "super_admin" || target.id === impersonator.id) return null;
  const { token, csrfToken } = createUserSession(target.id, impersonator.id);
  return { token, csrfToken, user: publicUser(target), impersonator: publicUser(impersonator) };
};

export const attachSession = (req: Request, _res: Response, next: NextFunction) => {
  const bearer = bearerToken(req.get("authorization"));
  if (bearer) {
    const apiToken = apiTokens.findByHash(hashToken(bearer));
    const user = apiToken ? users.findById(apiToken.userId) : null;
    if (apiToken && user) {
      req.apiToken = apiToken;
      req.user = user;
      apiTokens.markUsed(apiToken.id);
      return next();
    }
  }
  const token = req.cookies?.[cookieName];
  if (!token) return next();
  const session = sessions.find(token);
  if (!session) return next();
  const user = users.findById(session.user_id);
  if (user) {
    req.user = user;
    req.csrfToken = session.csrf_token;
    if (session.impersonator_user_id) req.impersonator = users.findById(session.impersonator_user_id) ?? undefined;
  }
  next();
};

export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  if (!req.user) return res.status(401).json({ error: "Authentication required." });
  if (req.apiToken && !["GET", "HEAD", "OPTIONS"].includes(req.method) && !req.apiToken.scopes.includes("write")) {
    return res.status(403).json({ error: "API token does not allow write access." });
  }
  if (!req.apiToken && !["GET", "HEAD", "OPTIONS"].includes(req.method) && req.get("x-csrf-token") !== req.csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token." });
  }
  next();
};

export const resolveTenant = (req: Request, res: Response, next: NextFunction) => {
  if (!req.user) return next();
  const memberships = tenants.forUser(req.user.id);
  if (!memberships.length) return res.status(403).json({ error: "No organization membership found." });
  const requested = req.get("x-tenant-id");
  const membership = memberships.find((item) => item.tenantId === requested) ?? memberships[0];
  req.currentTenant = membership.tenant;
  req.tenantRole = membership.role;
  req.tenantMemberships = memberships;
  const availableTeams = teams.listForUser(membership.tenantId, req.user.id, req.tenantRole);
  req.teamMemberships = teamMemberships.activeForUser(membership.tenantId, req.user.id);
  const requestedTeam = req.get("x-team-id");
  const team = requestedTeam ? availableTeams.find((item) => item.id === requestedTeam) : undefined;
  req.currentTeam = team ?? availableTeams[0];
  req.teamRole = req.currentTeam ? req.teamMemberships.find((item) => item.teamId === req.currentTeam!.id)?.role : undefined;
  next();
};

export const requireTenantRole = (...roles: TenantRole[]) => (req: Request, res: Response, next: NextFunction) => {
  if (!req.tenantRole || !roles.includes(req.tenantRole)) {
    const needed = roles.length > 1 ? `${roles.slice(0, -1).join(", ")} or ${roles.at(-1)}` : roles[0];
    return res.status(403).json({ error: `This needs the ${needed} role in this organization, and your role is ${req.tenantRole ?? "none"}. Ask an owner of the organization for the role.` });
  }
  next();
};

export const requireTeamAccess = (req: Request, res: Response, next: NextFunction) => {
  if (!req.currentTeam) return res.status(404).json({ error: "Team not found in this organization." });
  if (req.tenantRole === "owner" || req.tenantRole === "admin" || req.currentTeam.visibility === "tenant_visible" || req.teamRole) return next();
  return res.status(403).json({ error: "Team permission required." });
};

export const requireTeamRole = (...roles: TeamRole[]) => (req: Request, res: Response, next: NextFunction) => {
  if (req.tenantRole === "owner" || req.tenantRole === "admin") return next();
  if (!req.teamRole || !roles.includes(req.teamRole)) return res.status(403).json({ error: "Team permission required." });
  next();
};

export const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
  if (req.user?.role !== "super_admin" && req.user?.role !== "admin") return res.status(403).json({ error: "Only platform administrators can do this. Ask an administrator of this crt.watch instance." });
  next();
};

export const requireSuperAdmin = (req: Request, res: Response, next: NextFunction) => {
  if (req.user?.role !== "super_admin" || req.impersonator) return res.status(403).json({ error: "Super admin role required." });
  next();
};

export const setSessionCookie = (res: Response, token: string) => {
  res.cookie(cookieName, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: env.cookieSecure,
    maxAge: 1000 * 60 * 60 * 24 * 14
  });
};

export const clearSessionCookie = (req: Request, res: Response) => {
  const token = req.cookies?.[cookieName];
  if (token) sessions.delete(token);
  res.clearCookie(cookieName);
};

export const publicUser = (user: AppUser) => ({ id: user.id, email: user.email, role: user.role, mfaEnabled: user.mfaEnabled });

export const createPlainApiToken = () => `cw_${randomToken(32)}`;
export const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");

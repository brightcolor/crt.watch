import type { Request, Response } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import { verifyMfaChallenge } from "../auth/tokens.js";
import { env } from "../config/env.js";

/* Two limits, both counted per client address (req.ip, which follows
   TRUST_PROXY):

   - a general one for every request, generous enough for the polling
     interface of a busy team behind one address, so a single client cannot
     flood the server with expensive requests;
   - a strict one for sign-in, registration and two-factor steps that counts
     only failed attempts, so guessing passwords and codes stalls quickly
     while a person who types correctly never notices it.

   The two-factor step is also counted per account, because the code belongs
   to the account and changing addresses must not buy more guesses. */

export type RequestLimitSettings = { windowSeconds: number; maxRequests: number };
export type AuthLimitSettings = { windowMinutes: number; maxAttempts: number };

const retryAfterSeconds = (req: Request, fallbackMs: number) => {
  const resetTime = (req as Request & { rateLimit?: { resetTime?: Date } }).rateLimit?.resetTime;
  return Math.max(1, Math.ceil(((resetTime?.getTime() ?? Date.now() + fallbackMs) - Date.now()) / 1000));
};

const waitText = (seconds: number) => (seconds < 120 ? `${seconds} seconds` : `${Math.ceil(seconds / 60)} minutes`);

// API clients read { error }; a browser that navigated here gets plain text.
const sendLimited = (req: Request, res: Response, status: number, message: string) => {
  if (req.originalUrl.startsWith("/api/") || req.accepts(["json", "html"]) === "json") return res.status(status).json({ error: message });
  return res.status(status).type("text/plain").send(message);
};

export const createRequestLimiter = (settings: RequestLimitSettings = { windowSeconds: env.rateLimitWindowSeconds, maxRequests: env.rateLimitMaxRequests }) =>
  rateLimit({
    windowMs: settings.windowSeconds * 1000,
    limit: settings.maxRequests,
    // 0 switches the limit off here; the library's warning about limit 0 would only confuse.
    skip: () => settings.maxRequests === 0,
    validate: { limit: false },
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (req, res, _next, options) => {
      const wait = retryAfterSeconds(req, settings.windowSeconds * 1000);
      sendLimited(req, res, options.statusCode, `Too many requests from your address: the limit is ${settings.maxRequests} requests in ${settings.windowSeconds} seconds. Wait ${waitText(wait)} and try again.`);
    }
  });

const authHandler = (settings: AuthLimitSettings, subject: string) =>
  (req: Request, res: Response, _next: unknown, options: { statusCode: number }) => {
    const wait = retryAfterSeconds(req, settings.windowMinutes * 60_000);
    sendLimited(req, res, options.statusCode, `Too many failed attempts ${subject}: at most ${settings.maxAttempts} are allowed in ${settings.windowMinutes} minutes. Wait ${waitText(wait)} and try again.`);
  };

const authDefaults = (): AuthLimitSettings => ({ windowMinutes: env.authRateLimitWindowMinutes, maxAttempts: env.authRateLimitMaxAttempts });

/** Failed sign-in, registration, setup and two-factor requests per client address. */
export const createAuthLimiter = (settings: AuthLimitSettings = authDefaults()) =>
  rateLimit({
    windowMs: settings.windowMinutes * 60_000,
    limit: settings.maxAttempts,
    skipSuccessfulRequests: true,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: authHandler(settings, "from your address")
  });

/** Failed two-factor codes per account, taken from the signed challenge of the first sign-in step. */
export const createMfaAccountLimiter = (settings: AuthLimitSettings = authDefaults()) =>
  rateLimit({
    windowMs: settings.windowMinutes * 60_000,
    limit: settings.maxAttempts,
    skipSuccessfulRequests: true,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    keyGenerator: (req) => {
      const userId = verifyMfaChallenge(String(req.body?.mfaToken ?? ""));
      return userId ? `mfa-account:${userId}` : ipKeyGenerator(req.ip ?? "");
    },
    handler: authHandler(settings, "for this account")
  });

export const requestLimiter = createRequestLimiter();
export const authLimiter = createAuthLimiter();
export const mfaAccountLimiter = createMfaAccountLimiter();

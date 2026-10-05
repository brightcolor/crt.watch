import { timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

/* Every request that changes something passes this check before the /api routes.

   A request signed in with the session cookie carries the CSRF token of its
   session in the X-CSRF-Token header. The web interface receives the token at
   sign-in and from /api/auth/me and sends it with every request. A request
   with an API token in the Authorization header carries its credentials
   itself and needs no CSRF token.

   Sign-in, registration and the first-run setup start a session, so a request
   without a session is accepted as JSON only: browsers send JSON to crt.watch
   from pages of crt.watch itself, because crt.watch allows no other origin. A
   request without a body goes on to its route, which answers it. */

const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

/** Compares two CSRF tokens in constant time; an empty or missing token never matches. */
export const csrfTokensEqual = (provided: string | undefined, expected: string | undefined) => {
  if (!provided || !expected) return false;
  const given = Buffer.from(provided);
  const wanted = Buffer.from(expected);
  return given.length === wanted.length && timingSafeEqual(given, wanted);
};

export const missingCsrfToken = "This change was refused because the request did not carry the security token of your session. Reload the page and try again; if it keeps failing, sign out and sign in again.";

export const jsonRequired = "crt.watch accepts this request as JSON only (Content-Type: application/json). The web interface sends it that way; scripts send JSON as well, or use an API token in the Authorization header.";

export const csrfProtection = (req: Request, res: Response, next: NextFunction) => {
  if (safeMethods.has(req.method) || req.apiToken) return next();
  if (req.session) {
    if (csrfTokensEqual(req.get("x-csrf-token"), req.session.csrfToken)) return next();
    return res.status(403).json({ error: missingCsrfToken });
  }
  if (!req.get("content-type") || req.is("application/json")) return next();
  res.status(415).json({ error: jsonRequired });
};

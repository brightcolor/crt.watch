import path from "node:path";
import type { Request, Response } from "express";
import { setupPath, setupRequired } from "../auth/setup.js";
import { env } from "../config/env.js";
import { renderFrontPageDocument } from "./frontPage.js";

/* Two halves, split by address.

     /            front page, rendered here so crawlers see it
     /login       sign in
     /register    create an organization
     /app/…       the application, behind a session
     /setup       the first-run setup, only while no administrator exists

   Sending each visitor to the half they belong in keeps a shared link honest:
   /app opens the application or asks you to sign in first, and never shows a
   marketing page to somebody who is already working.

   While no administrator exists, every page leads to /setup. The API, the
   public status pages and badges, /metrics and the static files are served
   before this handler and stay reachable. Once an administrator exists,
   /setup answers 404. */

export const APP_PREFIX = "/app";
const isAppPath = (value: string) => value === APP_PREFIX || value.startsWith(`${APP_PREFIX}/`);
const isAuthPath = (value: string) => value === "/login" || value === "/register";

export const setupClosedPage = "The setup of this crt.watch instance is complete. Sign in at /login.";

export const pageHandler = (webDist: string, frontPageEnabled = env.frontPageEnabled) => (req: Request, res: Response) => {
  const signedIn = Boolean(req.user);
  const requestPath = req.path.replace(/\/+$/, "") || "/";
  const shell = path.join(webDist, "index.html");

  if (setupRequired()) {
    if (requestPath !== setupPath) return res.redirect(302, setupPath);
    return res.sendFile(shell);
  }
  if (requestPath === setupPath) return res.status(404).type("text/plain").send(setupClosedPage);

  // An invite carries its token in the query; keep it on any redirect.
  const query = req.originalUrl.includes("?") ? req.originalUrl.slice(req.originalUrl.indexOf("?")) : "";

  if (signedIn && (requestPath === "/" || isAuthPath(requestPath))) return res.redirect(302, APP_PREFIX);
  if (!signedIn && isAppPath(requestPath)) {
    const target = frontPageEnabled ? "/login" : "/";
    return res.redirect(302, `${target}${query}`);
  }

  if (requestPath === "/") {
    const document = renderFrontPageDocument(signedIn);
    if (document) return res.type("html").send(document);
  }

  res.sendFile(shell);
};

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express, NextFunction, Request, Response } from "express";

/**
 * Puts the Cookie header into req.cookies, which is all the session lookup
 * needs from cookie-parser; the CSRF check of requireAuth runs unchanged.
 */
export const readCookies = (req: Request, _res: Response, next: NextFunction) => {
  req.cookies = Object.fromEntries((req.headers.cookie ?? "").split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const separator = part.indexOf("=");
    return separator < 0 ? [part, ""] : [part.slice(0, separator), decodeURIComponent(part.slice(separator + 1))];
  }));
  next();
};

export type Session = { token: string; csrfToken: string };

export type CallOptions = { session?: Session; tenantId?: string; bearer?: string; headers?: Record<string, string>; redirect?: RequestRedirect };

export type CallResult = { status: number; text: string; headers: Headers; json: () => any };

/** Starts the app on a free local port and returns a client for it. */
export const serve = async (app: Express) => {
  const server: Server = await new Promise((resolve) => {
    const started = app.listen(0, "127.0.0.1", () => resolve(started));
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const call = async (method: string, route: string, body?: unknown, options: CallOptions = {}): Promise<CallResult> => {
    const headers: Record<string, string> = { accept: "application/json", ...options.headers };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (options.session) {
      headers.cookie = `crtwatch_session=${options.session.token}`;
      headers["x-csrf-token"] = options.session.csrfToken;
    }
    if (options.tenantId) headers["x-tenant-id"] = options.tenantId;
    if (options.bearer) headers.authorization = `Bearer ${options.bearer}`;
    const response = await fetch(`${base}${route}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: options.redirect ?? "follow" });
    const text = await response.text();
    return { status: response.status, text, headers: response.headers, json: () => JSON.parse(text) };
  };

  const close = async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };

  return { base, call, close };
};

import type { ErrorRequestHandler, NextFunction, Request, Response, Router } from "express";
import { logFailure } from "../utils/failures.js";

/* Express 4 calls a handler and leaves whatever it returns alone. Once a
   router has all its routes, forwardRejections wraps every handler in it and
   in the routers below it: when a handler returns a promise that rejects, the
   error goes to next(), and errorHandler answers it like an error the handler
   throws. routes/index.ts applies it to /api, publicRoutes.ts to /public; the
   handlers that server.ts mounts on the app itself are synchronous. */

type Handler = (...args: never[]) => unknown;
type Layer = { handle: Handler; route?: { stack: Layer[] } };
type RouterStack = Handler & { stack: Layer[] };

const forwards = Symbol("forwards rejections to next()");
type Wrapped = Handler & { [forwards]?: true };

const isRouter = (handler: Handler): handler is RouterStack => Array.isArray((handler as Partial<RouterStack>).stack);

/** Whether the handler hands the rejection of its promise to next(). */
export const forwardsRejections = (handler: Handler) => (handler as Wrapped)[forwards] === true;

const settle = (returned: unknown, next: NextFunction) => {
  if (typeof (returned as PromiseLike<unknown> | undefined)?.then !== "function") return;
  (returned as PromiseLike<unknown>).then(undefined, (reason: unknown) =>
    next(reason instanceof Error ? reason : new Error(`A request handler failed with: ${String(reason)}`)));
};

// Express tells error middleware (four parameters) from other handlers by their length, so the wrapper keeps it.
const wrap = (handler: Handler): Handler => {
  if (forwardsRejections(handler) || handler.length > 4) return handler;
  const call = handler as (...args: unknown[]) => unknown;
  const wrapped: Wrapped = handler.length === 4
    ? function (this: unknown, error: unknown, req: Request, res: Response, next: NextFunction) { settle(call.call(this, error, req, res, next), next); }
    : function (this: unknown, req: Request, res: Response, next: NextFunction) { settle(call.call(this, req, res, next), next); };
  wrapped[forwards] = true;
  return wrapped;
};

/** Makes every handler of the router, and of the routers below it, hand a rejected promise to next(). */
export const forwardRejections = <T extends Router>(router: T): T => {
  for (const layer of (router as unknown as RouterStack).stack) {
    if (layer.route) for (const step of layer.route.stack) step.handle = wrap(step.handle);
    else if (isRouter(layer.handle)) forwardRejections(layer.handle as unknown as Router);
    else layer.handle = wrap(layer.handle);
  }
  return router;
};

/* The answer to an error at the end of the chain. A request that crt.watch
   refuses, such as a body that is not JSON or too large, gets the status the
   error carries and a message that says what to change; such errors mark
   themselves with a 4xx status and expose, as the body parsers do. Every
   other error is logged with a reference, and the answer is 500 with that
   reference, so the operator finds the entry in the server log. When the
   answer has already begun, the connection is closed, which tells the client
   that the answer is incomplete. */

type HttpError = { status?: unknown; statusCode?: unknown; type?: unknown; expose?: unknown; limit?: unknown; message?: unknown };

const size = (bytes: number) => (bytes >= 1024 * 1024 ? `${Math.round(bytes / (1024 * 1024))} MB` : `${Math.round(bytes / 1024)} KB`);

// Error types of the body parsers (body-parser and raw-body).
const bodyRefusals: Record<string, (error: HttpError) => string> = {
  "entity.parse.failed": () => "The request body is not valid JSON. Check its syntax and send it again.",
  "entity.too.large": (error) => `The request body is larger than crt.watch accepts${typeof error.limit === "number" ? ` (${size(error.limit)})` : ""}. Send a smaller body, for example by importing fewer monitors at once.`,
  "charset.unsupported": () => "The request body uses a character set that crt.watch cannot read. Send it as UTF-8.",
  "encoding.unsupported": () => "The request body uses a content encoding that crt.watch cannot read. Send it uncompressed.",
  "request.aborted": () => "The request ended before its body arrived completely. Send it again.",
  "request.size.invalid": () => "The request body is shorter or longer than its Content-Length header says. Send it again."
};

/** Status and message for an error that refuses the request (4xx), or null for a failure on the server. */
export const refusal = (error: unknown): { status: number; message: string } | null => {
  const details = (error ?? {}) as HttpError;
  const status = Number(details.status ?? details.statusCode);
  if (!Number.isInteger(status) || status < 400 || status > 499 || details.expose !== true) return null;
  const known = typeof details.type === "string" ? bodyRefusals[details.type] : undefined;
  if (known) return { status, message: known(details) };
  const reason = typeof details.message === "string" && details.message ? `: ${details.message}` : "";
  return { status, message: `crt.watch could not process this request (HTTP ${status}${reason}). Check the address and the request, then try again.` };
};

export const serverErrorMessage = (reference: string) =>
  `crt.watch could not complete this request because of an error on the server. Try again; if it keeps failing, ask the operator to look up reference ${reference} in the server log.`;

export const errorHandler: ErrorRequestHandler = (error, req, res, _next) => {
  const refused = refusal(error);
  if (refused && !res.headersSent) return res.status(refused.status).json({ error: refused.message });
  // The path without its query, which can carry tokens such as invitations.
  const reference = logFailure(`Request ${req.method} ${req.originalUrl.split("?")[0]} failed`, error);
  if (res.headersSent) return req.socket.destroy();
  res.status(500).json({ error: serverErrorMessage(reference) });
};

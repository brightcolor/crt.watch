import type { NextFunction, Request, Response } from "express";
import type { TrustProxy } from "../config/env.js";

/* The client address decides which rate limit a request counts against. It
   comes from the connection unless TRUST_PROXY names the proxies whose
   X-Forwarded-For header may replace it. These helpers tell the operator in
   the log which of the two is in effect. */

export const describeProxyTrust = (trust: TrustProxy) => {
  if (trust === false) return "Client addresses come from the connection; X-Forwarded-For is ignored (TRUST_PROXY=false).";
  if (typeof trust === "number") {
    return `Client addresses come from X-Forwarded-For, trusting ${trust} proxy ${trust === 1 ? "hop" : "hops"} from any address (TRUST_PROXY). Make sure nothing but the proxy can reach crt.watch, or name the proxy instead, for example TRUST_PROXY=loopback,uniquelocal.`;
  }
  return `Client addresses come from X-Forwarded-For when the request arrives from ${trust.join(", ")} (TRUST_PROXY).`;
};

export const forwardedHeaderHint = "A request arrived with an X-Forwarded-For header, but TRUST_PROXY is off, so crt.watch counts it under the address of the connection. If crt.watch runs behind a reverse proxy, set TRUST_PROXY to the address or network of the proxy, for example TRUST_PROXY=loopback,uniquelocal, so the rate limits count each visitor by their own address.";

/** Logs once when proxy headers arrive while TRUST_PROXY is off. */
export const reportIgnoredForwardedHeader = (trust: TrustProxy, log: (message: string) => void = console.warn) => {
  let reported = false;
  return (req: Request, _res: Response, next: NextFunction) => {
    if (trust === false && !reported && req.headers["x-forwarded-for"]) {
      reported = true;
      log(forwardedHeaderHint);
    }
    next();
  };
};

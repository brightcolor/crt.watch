import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import { env } from "./config/env.js";
import { attachSession } from "./auth/auth.js";
import { configurePassport } from "./auth/passport.js";
import { db, migrate } from "./storage/db.js";
import { apiRoutes } from "./routes/index.js";
import { publicRoutes } from "./routes/publicRoutes.js";
import { metricsHandler } from "./routes/metrics.js";
import { startScheduler } from "./scheduler/scheduler.js";
import { loadFrontPageRenderer, renderFrontPageDocument } from "./render/frontPage.js";
import { securityHeaders } from "./security/headers.js";
import { requestLimiter } from "./security/rateLimits.js";

migrate();

const app = express();
if (env.trustProxy) app.set("trust proxy", 1);

app.use(securityHeaders());
// Logged before the limit so refused requests show up in the access log too;
// limited before the body parsers so a flood is turned away cheaply.
app.use(morgan(env.nodeEnv === "production" ? "combined" : "dev"));
app.use(requestLimiter);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));
app.use(cookieParser(env.sessionSecret));
app.use(configurePassport());
app.use(attachSession);
app.get("/metrics", metricsHandler);
app.use("/api", apiRoutes);
app.use("/public", publicRoutes);

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const webDist = path.resolve(currentDir, "../../web/dist");
app.use(express.static(webDist, { index: false }));

/* Two halves, split by address.

     /            front page, rendered here so crawlers see it
     /login       sign in
     /register    create an organization
     /app/…       the application, behind a session

   Sending each visitor to the half they belong in keeps a shared link honest:
   /app opens the application or asks you to sign in first, and never shows a
   marketing page to somebody who is already working. */
const APP_PREFIX = "/app";
const isAppPath = (value: string) => value === APP_PREFIX || value.startsWith(`${APP_PREFIX}/`);
const isAuthPath = (value: string) => value === "/login" || value === "/register";

app.get("*", (req, res) => {
  const signedIn = Boolean(req.user);
  const requestPath = req.path.replace(/\/+$/, "") || "/";

  // An invite carries its token in the query; keep it on any redirect.
  const query = req.originalUrl.includes("?") ? req.originalUrl.slice(req.originalUrl.indexOf("?")) : "";

  if (signedIn && (requestPath === "/" || isAuthPath(requestPath))) return res.redirect(302, APP_PREFIX);
  if (!signedIn && isAppPath(requestPath)) {
    const target = env.frontPageEnabled ? "/login" : "/";
    return res.redirect(302, `${target}${query}`);
  }

  if (requestPath === "/") {
    const document = renderFrontPageDocument(signedIn);
    if (document) return res.type("html").send(document);
  }

  res.sendFile(path.join(webDist, "index.html"));
});

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error." });
});

await loadFrontPageRenderer(webDist);

app.listen(env.port, () => {
  console.log(`crt.watch listening on ${env.port}`);
  startScheduler();
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    db.flush();
    process.exit(0);
  });
}

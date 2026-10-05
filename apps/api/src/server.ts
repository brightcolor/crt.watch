import express from "express";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import { env } from "./config/env.js";
import { attachSession } from "./auth/auth.js";
import { configurePassport } from "./auth/passport.js";
import { announceSetup } from "./auth/setup.js";
import { db, migrate } from "./storage/db.js";
import { apiRoutes } from "./routes/index.js";
import { publicRoutes } from "./routes/publicRoutes.js";
import { metricsAccess, metricsHandler } from "./routes/metrics.js";
import { startScheduler } from "./scheduler/scheduler.js";
import { loadFrontPageRenderer } from "./render/frontPage.js";
import { pageHandler } from "./render/pages.js";
import { securityHeaders } from "./security/headers.js";
import { describeProxyTrust, reportIgnoredForwardedHeader } from "./security/proxy.js";
import { requestLimiter } from "./security/rateLimits.js";

migrate();

const app = express();
// TRUST_PROXY names the proxies whose X-Forwarded-For header gives the client address; off by default.
if (env.trustProxy !== false) app.set("trust proxy", env.trustProxy);
console.log(describeProxyTrust(env.trustProxy));
if (env.metricsAccess === "public") console.warn("METRICS_ACCESS=public: /metrics lists the monitors of every organization to anyone who can reach it.");

app.use(securityHeaders());
// Logged before the limit so refused requests show up in the access log too;
// limited before the body parsers so a flood is turned away cheaply.
app.use(morgan(env.nodeEnv === "production" ? "combined" : "dev"));
app.use(reportIgnoredForwardedHeader(env.trustProxy));
app.use(requestLimiter);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));
app.use(cookieParser(env.sessionSecret));
app.use(configurePassport());
app.use(attachSession);
app.get("/metrics", metricsAccess(), metricsHandler);
app.use("/api", apiRoutes);
app.use("/public", publicRoutes);

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const webDist = path.resolve(currentDir, "../../web/dist");
app.use(express.static(webDist, { index: false }));
// Pages of the front and of the application; while no administrator exists, every page leads to /setup.
app.get("*", pageHandler(webDist));

// The reference ties the answer to its entry in the server log.
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const reference = randomUUID().slice(0, 8);
  console.error(`Request failed (reference ${reference}):`, err);
  res.status(500).json({ error: `crt.watch could not complete this request because of an error on the server. Try again; if it keeps failing, ask the operator to look up reference ${reference} in the server log.` });
});

await loadFrontPageRenderer(webDist);
announceSetup(env.baseUrl);

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

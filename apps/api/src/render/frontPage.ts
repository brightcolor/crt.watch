import fs from "node:fs";
import path from "node:path";
import { env } from "../config/env.js";
import { publicRegistrationEnabled } from "../routes/authRoutes.js";
import { users } from "../storage/repositories.js";

type BootConfig = {
  setupRequired: boolean;
  frontPageEnabled: boolean;
  publicRegistrationEnabled: boolean;
};

type Renderer = (config: BootConfig) => string;

/* Server-side rendering for the one page that is public: the front page.
   Everything else needs a session, so a crawler never reaches it and rendering
   it here would only add latency.

   The server bundle is optional. When it is missing — during development, or
   if the web build was skipped — the shell is served unchanged and the client
   renders as before. */
let renderer: Renderer | null = null;
let shell: string | null = null;
let loaded = false;

const serverBundle = (webDist: string) => path.resolve(webDist, "../dist-server/entry-server.js");

export const loadFrontPageRenderer = async (webDist: string) => {
  if (loaded) return;
  loaded = true;
  const bundle = serverBundle(webDist);
  const indexPath = path.join(webDist, "index.html");
  try {
    if (!fs.existsSync(bundle) || !fs.existsSync(indexPath)) return;
    const module = await import(`file://${bundle}`);
    if (typeof module.renderFrontPage !== "function") return;
    renderer = module.renderFrontPage;
    shell = fs.readFileSync(indexPath, "utf8");
    console.log("front page will be rendered on the server");
  } catch (error) {
    // A broken bundle must never take the app down; fall back to the shell.
    console.error("front page server rendering disabled:", error);
    renderer = null;
    shell = null;
  }
};

/* The configuration travels as a JSON data block. The browser never executes
   it, so it passes the Content Security Policy without an inline-script
   exception; the client reads it by id. Escaping "<" keeps a value from closing
   the element early. */
export const bootConfigScript = (config: BootConfig) =>
  `<script type="application/json" id="crtwatch-boot">${JSON.stringify(config).replace(/</g, "\\u003c")}</script>`;

/* Returns the page with the front page already in it, or null when this request
   should get the plain shell: a signed-in visitor, a disabled front page, or a
   build without the server bundle. */
export const renderFrontPageDocument = (hasSession: boolean): string | null => {
  if (!renderer || !shell) return null;
  if (hasSession || !env.frontPageEnabled) return null;

  const config: BootConfig = {
    setupRequired: users.count() === 0,
    frontPageEnabled: env.frontPageEnabled,
    publicRegistrationEnabled: publicRegistrationEnabled()
  };

  // A fresh instance goes straight to creating the first admin.
  if (config.setupRequired) return null;

  try {
    const markup = renderer(config);
    // The client reads this instead of waiting for /auth/config, so its first
    // render matches the markup it is hydrating.
    return shell
      .replace('<div id="root"></div>', `<div id="root">${markup}</div>${bootConfigScript(config)}`);
  } catch (error) {
    console.error("front page render failed:", error);
    return null;
  }
};

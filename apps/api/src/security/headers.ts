import helmet from "helmet";
import { env } from "../config/env.js";

export type SecurityHeaderSettings = {
  contentSecurityPolicy: "enforce" | "report-only";
  imageSources: string[];
};

/* Content Security Policy for the application, the front page and the public
   status pages. Scripts, styles and fonts all come from this server, so a
   script injected into a page has nowhere to load from and nothing inline
   runs. The only foreign content is the logo of a custom status page, which
   CONTENT_SECURITY_POLICY_IMAGE_SOURCES allows. Inline styles stay allowed:
   the status pages carry a <style> block and React sets style attributes.

   upgrade-insecure-requests is left out on purpose. crt.watch also runs on
   plain HTTP inside a network, and the directive would make the browser ask
   for every asset over HTTPS there. */
export const contentSecurityPolicyDirectives = (settings: SecurityHeaderSettings) => ({
  "default-src": ["'self'"],
  "base-uri": ["'self'"],
  "connect-src": ["'self'"],
  "font-src": ["'self'", "data:"],
  "form-action": ["'self'"],
  "frame-ancestors": ["'self'"],
  "img-src": settings.imageSources,
  "object-src": ["'none'"],
  "script-src": ["'self'"],
  "script-src-attr": ["'none'"],
  "style-src": ["'self'", "'unsafe-inline'"]
});

export const securityHeaders = (settings: SecurityHeaderSettings = { contentSecurityPolicy: env.contentSecurityPolicy, imageSources: env.contentSecurityPolicyImageSources }) =>
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: contentSecurityPolicyDirectives(settings),
      reportOnly: settings.contentSecurityPolicy === "report-only"
    }
  });

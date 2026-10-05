import path from "node:path";
import { parseNetworkList } from "../utils/networks.js";

type SettingSource = Record<string, string | undefined>;

const numberFromEnv = (key: string, fallback: number) => {
  const value = Number(process.env[key]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
};

const boolFromEnv = (key: string, fallback: boolean) => {
  const value = process.env[key];
  if (value === undefined) return fallback;
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
};

/* The readers below validate what they read. A value outside its range stops
   the start with a message that names the variable, what it accepts and its
   default, so a typo never leaves a protection silently switched off. An unset
   or empty variable means the default. */
const correction = (fallback: string) =>
  `Correct it in the environment (for example in .env) or remove it to use the default of ${fallback}.`;

export const integerSetting = (source: SettingSource, key: string, fallback: number, min: number, max: number) => {
  const raw = source[key]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!/^-?\d+$/.test(raw) || value < min || value > max) {
    throw new Error(`${key} must be a whole number from ${min} to ${max}, but is set to "${raw}". ${correction(String(fallback))}`);
  }
  return value;
};

export const booleanSetting = (source: SettingSource, key: string, fallback: boolean) => {
  const raw = source[key]?.trim().toLowerCase();
  if (!raw) return fallback;
  if (["1", "true", "yes", "on"].includes(raw)) return true;
  if (["0", "false", "no", "off"].includes(raw)) return false;
  throw new Error(`${key} must be true or false, but is set to "${source[key]}". ${correction(String(fallback))}`);
};

export const choiceSetting = <T extends string>(source: SettingSource, key: string, fallback: T, choices: readonly T[]): T => {
  const raw = source[key]?.trim().toLowerCase();
  if (!raw) return fallback;
  const choice = choices.find((item) => item === raw);
  if (choice) return choice;
  throw new Error(`${key} must be one of ${choices.join(", ")}, but is set to "${source[key]}". ${correction(fallback)}`);
};

export const networkListSetting = (source: SettingSource, key: string) => parseNetworkList(source[key] ?? "", key);

/* Which peers may name the client address in X-Forwarded-For. false ignores the
   header, which is right for a container that clients reach directly. A list of
   addresses and networks trusts exactly the proxies in it, and Express's names
   loopback, linklocal and uniquelocal stand for their ranges. true and a number
   trust that many hops whatever their address, which fits a container that
   nothing but the proxy can reach. */
export type TrustProxy = false | number | string[];

const proxyRangeNames = ["loopback", "linklocal", "uniquelocal"];
const maxProxyHops = 10;

export const trustProxySetting = (source: SettingSource, key: string): TrustProxy => {
  const raw = source[key]?.trim();
  if (!raw) return false;
  const lower = raw.toLowerCase();
  if (["0", "false", "no", "off"].includes(lower)) return false;
  if (["true", "yes", "on"].includes(lower)) return 1;
  if (/^\d+$/.test(lower) && Number(lower) <= maxProxyHops) return Number(lower);
  const entries = raw.split(/[\s,]+/).filter(Boolean);
  const invalid = entries.find((entry) => {
    if (proxyRangeNames.includes(entry.toLowerCase())) return false;
    try {
      parseNetworkList(entry, key);
      return false;
    } catch {
      return true;
    }
  });
  if (invalid !== undefined) {
    throw new Error(`${key} must be false, true, a number of proxy hops from 1 to ${maxProxyHops}, or a list of proxy addresses and networks such as loopback, uniquelocal, 172.18.0.0/16 or 10.0.0.5, but "${invalid}" in "${raw}" is none of these. ${correction("false")}`);
  }
  return entries.map((entry) => (proxyRangeNames.includes(entry.toLowerCase()) ? entry.toLowerCase() : entry));
};

/* A secret such as a bearer token: at least minLength characters, and without
   spaces, because it travels in a header. The value never appears in the
   message. */
export const secretSetting = (source: SettingSource, key: string, minLength: number, whenUnset: string) => {
  const raw = source[key]?.trim();
  if (!raw) return "";
  if (raw.length < minLength || /\s/.test(raw)) {
    throw new Error(`${key} must be at least ${minLength} characters long and contain no spaces, but the value set has ${raw.length} characters${/\s/.test(raw) ? " and contains spaces" : ""}. Generate one with "openssl rand -hex 32", or remove ${key} to ${whenUnset}.`);
  }
  return raw;
};

// Keywords may be written without their quotes, because quotes are awkward in
// .env and Compose files: "self data: https:" is read as 'self' data: https:.
const cspKeywords: Record<string, string> = { self: "'self'", "'self'": "'self'", none: "'none'", "'none'": "'none'" };
const cspSourcePattern = /^([a-z][a-z0-9+.-]*:|(https?:\/\/)?(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*(:(\d{1,5}|\*))?(\/[^\s;,'"]*)?)$/i;

export const cspSourceListSetting = (source: SettingSource, key: string, fallback: string[]) => {
  const raw = source[key]?.trim();
  if (!raw) return fallback;
  return raw.split(/\s+/).map((entry) => {
    const keyword = cspKeywords[entry.toLowerCase()];
    if (keyword) return keyword;
    if (cspSourcePattern.test(entry)) return entry;
    throw new Error(`${key} contains "${entry}", which is not a Content Security Policy source. Use entries such as self, data:, https: or https://cdn.example.com, separated by spaces. ${correction(fallback.join(" "))}`);
  });
};

export const env = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: numberFromEnv("PORT", 8080),
  baseUrl: process.env.BASE_URL ?? "http://localhost:8080",
  databasePath: process.env.DATABASE_PATH ?? path.resolve("data/crtwatch.sqlite"),
  sessionSecret: process.env.SESSION_SECRET ?? "dev-only-change-me",
  // Peers that may set the client address in X-Forwarded-For; off unless the operator names the proxy.
  trustProxy: trustProxySetting(process.env, "TRUST_PROXY"),
  cookieSecure: boolFromEnv("COOKIE_SECURE", false),
  frontPageEnabled: boolFromEnv("FRONT_PAGE_ENABLED", true),
  publicRegistrationEnabled: boolFromEnv("PUBLIC_REGISTRATION_ENABLED", true),
  allowPrivateTargets: boolFromEnv("ALLOW_PRIVATE_TARGETS", false),
  checkConcurrency: numberFromEnv("CHECK_CONCURRENCY", 4),
  autoBackupIntervalHours: numberFromEnv("AUTO_BACKUP_INTERVAL_HOURS", 24),
  autoBackupKeep: numberFromEnv("AUTO_BACKUP_KEEP", 14),
  autoBackupEnabled: boolFromEnv("AUTO_BACKUP_ENABLED", true),
  defaultIntervalSeconds: numberFromEnv("DEFAULT_INTERVAL_SECONDS", 3600),
  defaultWarningDays: numberFromEnv("DEFAULT_WARNING_DAYS", 30),
  defaultCriticalDays: numberFromEnv("DEFAULT_CRITICAL_DAYS", 7),
  githubClientId: process.env.GITHUB_CLIENT_ID ?? "",
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET ?? "",
  githubCallbackUrl: process.env.GITHUB_CALLBACK_URL ?? `${process.env.BASE_URL ?? "http://localhost:8080"}/api/auth/github/callback`,
  // Webhook and chat notifications: which addresses they may reach and how long one may take.
  allowPrivateNotificationTargets: booleanSetting(process.env, "ALLOW_PRIVATE_NOTIFICATION_TARGETS", false),
  notificationAllowedNetworks: networkListSetting(process.env, "NOTIFICATION_ALLOWED_NETWORKS"),
  notificationMaxRedirects: integerSetting(process.env, "NOTIFICATION_MAX_REDIRECTS", 3, 0, 10),
  notificationTimeoutSeconds: integerSetting(process.env, "NOTIFICATION_TIMEOUT_SECONDS", 10, 1, 120),
  // Requests per client address and window; RATE_LIMIT_MAX_REQUESTS=0 switches this general limit off.
  rateLimitWindowSeconds: integerSetting(process.env, "RATE_LIMIT_WINDOW_SECONDS", 60, 1, 3600),
  rateLimitMaxRequests: integerSetting(process.env, "RATE_LIMIT_MAX_REQUESTS", 1200, 0, 100_000),
  // Failed sign-in, registration and two-factor attempts per window, per client address and per account.
  authRateLimitWindowMinutes: integerSetting(process.env, "AUTH_RATE_LIMIT_WINDOW_MINUTES", 15, 1, 1440),
  authRateLimitMaxAttempts: integerSetting(process.env, "AUTH_RATE_LIMIT_MAX_ATTEMPTS", 10, 1, 1000),
  // Content Security Policy on every response; report-only lets the browser log violations instead of blocking them.
  contentSecurityPolicy: choiceSetting(process.env, "CONTENT_SECURITY_POLICY", "enforce", ["enforce", "report-only"] as const),
  contentSecurityPolicyImageSources: cspSourceListSetting(process.env, "CONTENT_SECURITY_POLICY_IMAGE_SOURCES", ["'self'", "data:", "https:"]),
  // /metrics: authenticated answers to METRICS_TOKEN, a session or an API token; public answers everyone.
  metricsAccess: choiceSetting(process.env, "METRICS_ACCESS", "authenticated", ["authenticated", "public"] as const),
  metricsToken: secretSetting(process.env, "METRICS_TOKEN", 32, "let only signed-in users and API tokens read /metrics"),
  // Shortest password accepted for every account: setup, registration, user management and password changes.
  passwordMinLength: integerSetting(process.env, "PASSWORD_MIN_LENGTH", 12, 8, 128)
};

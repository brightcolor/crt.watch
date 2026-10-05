import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { appSettings, users } from "../storage/repositories.js";

/* First-run setup.

   While no platform administrator exists, every page of the application leads
   to /setup, where the operator creates the first administrator account. The
   setup asks for a setup code that only the operator sees: the server writes
   it to its log at every start, and the setup-code command prints it inside
   the container.

   The code is kept in the settings table, encrypted with SESSION_SECRET, so
   the server and the command read the same one. A new code replaces the old
   one at every start; the setup deletes it, and from then on /setup answers
   404 and the command reports that the setup is complete. */

export const setupPath = "/setup";
export const setupCodeCommand = "docker compose exec crt-watch node apps/api/dist/cli.js setup-code";

const settingKey = "setup";
// 32 signs without 0, O, 1 and I, so a code read from a log is typed correctly;
// 16 of them carry 80 random bits. 256 is a multiple of 32, so byte % 32 is even.
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const codeLength = 16;

type StoredSetup = { secret: string; issuedAt: string };

export const setupRequired = () => users.countAdmins() === 0;

export const issueSetupCode = () => {
  const signs = Array.from(randomBytes(codeLength), (byte) => alphabet[byte % alphabet.length]).join("");
  const code = signs.match(/.{4}/g)!.join("-");
  appSettings.set<StoredSetup>(settingKey, { secret: code, issuedAt: new Date().toISOString() });
  return code;
};

export const currentSetupCode = () => appSettings.get<StoredSetup>(settingKey, { secret: "", issuedAt: "" }).secret || null;

export const clearSetupCode = () => appSettings.delete(settingKey);

// Case, spaces and hyphens do not matter when the code is typed.
const normalized = (value: string) => value.toUpperCase().replace(/[^A-Z0-9]/g, "");
const digest = (value: string) => createHash("sha256").update(normalized(value)).digest();

export const setupCodeMatches = (input: string) => {
  const current = currentSetupCode();
  if (!current || !normalized(input)) return false;
  return timingSafeEqual(digest(input), digest(current));
};

/**
 * Prepares the setup when the server starts: a fresh code in the log while no
 * administrator exists, and no stored code once one does.
 */
export const announceSetup = (baseUrl: string, log: (message: string) => void = console.log) => {
  if (!setupRequired()) {
    clearSetupCode();
    return null;
  }
  const code = issueSetupCode();
  log([
    "crt.watch is not set up yet: no administrator account exists.",
    `Open ${baseUrl.replace(/\/$/, "")}${setupPath} and create the first administrator with this setup code: ${code}`,
    `The code changes at every start. To print the current one: ${setupCodeCommand}`
  ].join("\n"));
  return code;
};

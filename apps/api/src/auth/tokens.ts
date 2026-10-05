import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { env } from "../config/env.js";

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("hex");

/**
 * The token of an "Authorization: Bearer <token>" header. Whitespace and token
 * characters are disjoint in the pattern, so it matches in linear time however
 * long the header is; `.+` after `\s+` backtracked quadratically on runs of spaces.
 */
export const bearerToken = (header: string | undefined) => header?.match(/^Bearer\s+(\S+)$/i)?.[1];

const MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;

export const createMfaChallenge = (userId: string) => {
  const expiresAt = Date.now() + MFA_CHALLENGE_TTL_MS;
  const payload = `${userId}.${expiresAt}`;
  const signature = createHmac("sha256", env.sessionSecret).update(payload).digest("hex");
  return `${payload}.${signature}`;
};

export const verifyMfaChallenge = (challenge: string): string | null => {
  const parts = challenge.split(".");
  if (parts.length !== 3) return null;
  const [userId, expiresAtRaw, signature] = parts;
  const payload = `${userId}.${expiresAtRaw}`;
  const expected = createHmac("sha256", env.sessionSecret).update(payload).digest("hex");
  const signatureBuffer = Buffer.from(signature, "hex");
  const expectedBuffer = Buffer.from(expected, "hex");
  if (signatureBuffer.length !== expectedBuffer.length || !timingSafeEqual(signatureBuffer, expectedBuffer)) return null;
  if (Number(expiresAtRaw) < Date.now()) return null;
  return userId;
};

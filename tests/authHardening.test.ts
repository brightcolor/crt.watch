import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { bearerToken } from "../apps/api/src/auth/tokens.js";
import { tlsLoginAllowed } from "../apps/api/src/checks/tlsChecker.js";
import { env } from "../apps/api/src/config/env.js";
import { decryptSecret, encryptSecret } from "../apps/api/src/utils/secrets.js";

const cipher = vi.hoisted(() => ({ decipherOptions: [] as unknown[] }));

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return {
    ...actual,
    createDecipheriv: (...args: Parameters<typeof actual.createDecipheriv>) => {
      cipher.decipherOptions.push(args[3]);
      return actual.createDecipheriv(...args);
    }
  };
});

describe("bearer token header", () => {
  it("reads the token of a bearer header", () => {
    expect(bearerToken("Bearer cw_abc123")).toBe("cw_abc123");
    expect(bearerToken("bearer \t cw_abc123")).toBe("cw_abc123");
    expect(bearerToken("Basic dXNlcjpwYXNz")).toBeUndefined();
    expect(bearerToken("Bearer two words")).toBeUndefined();
    expect(bearerToken(undefined)).toBeUndefined();
  });

  it("answers in linear time for long runs of whitespace", () => {
    const started = performance.now();
    expect(bearerToken(`Bearer ${" ".repeat(100_000)}\n`)).toBeUndefined();
    expect(bearerToken(`bearer ${"\t ".repeat(100_000)}x y`)).toBeUndefined();
    expect(performance.now() - started).toBeLessThan(500);
  });
});

describe("stored secrets", () => {
  it("round-trips and asks GCM for the full 16-byte tag", () => {
    cipher.decipherOptions.length = 0;
    expect(decryptSecret(encryptSecret("smtp-password"))).toBe("smtp-password");
    expect(cipher.decipherOptions).toEqual([{ authTagLength: 16 }]);
  });

  it("rejects values whose tag was shortened or altered", () => {
    // The enc:v1 layout fixes the tag at 16 bytes; a value with a 4-byte tag is refused.
    const key = createHash("sha256").update(env.sessionSecret).digest();
    const iv = randomBytes(12);
    const shortTagCipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 4 });
    shortTagCipher.final();
    const shortTag = `enc:v1:${Buffer.concat([iv, shortTagCipher.getAuthTag()]).toString("base64url")}`;
    expect(decryptSecret(shortTag)).toBe("");

    const stored = Buffer.from(encryptSecret("api-key").slice("enc:v1:".length), "base64url");
    stored[20] ^= 1;
    expect(decryptSecret(`enc:v1:${stored.toString("base64url")}`)).toBe("");
  });
});

describe("credentials over TLS", () => {
  const strict = { validateCertificate: true, allowSelfSigned: false };

  it("are sent when the certificate is trusted for the host", () => {
    expect(tlsLoginAllowed(strict, { authorized: true, hostnameMatch: true, selfSigned: false })).toBe(true);
  });

  it("are withheld from an untrusted or foreign certificate", () => {
    expect(tlsLoginAllowed(strict, { authorized: false, hostnameMatch: true, selfSigned: false })).toBe(false);
    expect(tlsLoginAllowed(strict, { authorized: false, hostnameMatch: true, selfSigned: true })).toBe(false);
    expect(tlsLoginAllowed({ validateCertificate: false, allowSelfSigned: true }, { authorized: false, hostnameMatch: false, selfSigned: true })).toBe(false);
  });

  it("follow the certificate choices the operator made for the monitor", () => {
    expect(tlsLoginAllowed({ validateCertificate: true, allowSelfSigned: true }, { authorized: false, hostnameMatch: true, selfSigned: true })).toBe(true);
    expect(tlsLoginAllowed({ validateCertificate: false, allowSelfSigned: false }, { authorized: false, hostnameMatch: true, selfSigned: false })).toBe(true);
  });
});

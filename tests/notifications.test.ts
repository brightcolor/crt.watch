import { describe, expect, it } from "vitest";
import { NotificationTargetError } from "../apps/api/src/notifications/delivery.js";
import { buildPayload, testChannel } from "../apps/api/src/notifications/service.js";
import type { CheckResult, Monitor, NotificationChannel } from "../apps/api/src/types.js";

describe("notification payload", () => {
  it("contains the required webhook fields", () => {
    const payload = buildPayload({ id: "m1", name: "Example", host: "example.com", port: 443 } as Monitor, {
      status: "CRITICAL",
      severity: "critical",
      message: "expires soon",
      checkedAt: "2026-05-12T10:00:00Z",
      daysRemaining: 7,
      validUntil: "2026-06-01T12:00:00Z",
      issuer: "Let's Encrypt",
      fingerprintSha256: "abc"
    } as CheckResult);
    expect(payload).toMatchObject({
      monitor_id: "m1",
      monitor_name: "Example",
      host: "example.com",
      status: "critical",
      severity: "critical",
      days_remaining: 7
    });
  });
});

describe("notification channels", () => {
  const channel = (type: string, config: Record<string, unknown>) =>
    ({ id: "c1", tenantId: "t1", name: "Ops", type, enabled: true, config }) as NotificationChannel;

  it("refuse webhook and chat targets inside the local network by default", async () => {
    await expect(testChannel(channel("webhook", { url: "http://127.0.0.1:9/hook" }))).rejects.toBeInstanceOf(NotificationTargetError);
    await expect(testChannel(channel("gotify", { url: "http://169.254.169.254/message" }))).rejects.toBeInstanceOf(NotificationTargetError);
    await expect(testChannel(channel("matrix", { baseUrl: "http://localhost:8008", roomId: "!room:example.com", accessToken: "token" }))).rejects.toBeInstanceOf(NotificationTargetError);
  });
});

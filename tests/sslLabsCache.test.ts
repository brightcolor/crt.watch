import { removeDatabase } from "./support/isolatedDatabase.js";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/* A monitor reuses a recent SSL Labs assessment of its host from its own
   organization. The TLS check and the SSL Labs API are replaced, so the test
   opens no connection. */

vi.mock("../apps/api/src/checks/tlsChecker.js", () => ({
  runTlsCheck: vi.fn(async (monitor: { id: string }) => ({
    id: `tls-${monitor.id}`,
    monitorId: monitor.id,
    status: "OK",
    severity: "info",
    message: "Certificate and TLS configuration look healthy.",
    checkedAt: new Date().toISOString(),
    durationMs: 50,
    daysRemaining: 60,
    subjectAltNames: [],
    chain: [],
    problems: []
  }))
}));

import { migrate } from "../apps/api/src/storage/db.js";
import { appSettings, results } from "../apps/api/src/storage/repositories.js";
import { runMonitorCheck } from "../apps/api/src/checks/monitorRunner.js";
import { monitorIn, organization, resultFor } from "./support/fixtures.js";

migrate();

const host = "shared.example.com";
const sslLabsMonitor = { host, port: 443, type: "https" as const, config: { sslLabsEnabled: true, dnsCheckEnabled: false } };
const enableSslLabs = (tenantId: string) =>
  appSettings.set("sslLabs", { enabled: true, registeredEmail: "ops@example.com", intervalHours: 24, maxAgeHours: 24, timeoutSeconds: 15, startNewScans: false, publishResults: false }, tenantId);

const alpha = organization("Alpha");
const beta = organization("Beta");
enableSslLabs(alpha.tenant.id);
enableSslLabs(beta.tenant.id);
const betaAssessed = monitorIn(beta.tenant.id, sslLabsMonitor);
results.insert(resultFor(betaAssessed, { sslLabsGrade: "A+", sslLabsScore: 100, sslLabsStatus: "READY", sslLabsCheckedAt: new Date().toISOString() }));

let sslLabsApi: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  sslLabsApi = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify({ status: "READY", endpoints: [{ ipAddress: "203.0.113.10", grade: "B" }] })));
});
afterEach(() => vi.restoreAllMocks());
afterAll(() => removeDatabase());

describe("SSL Labs assessments", () => {
  it("are reused within the organization that ran them", async () => {
    const betaSibling = monitorIn(beta.tenant.id, sslLabsMonitor);

    const result = await runMonitorCheck(betaSibling);

    expect(result.sslLabsGrade).toBe("A+");
    expect(sslLabsApi).not.toHaveBeenCalled();
  });

  it("of another organization leave a monitor to run its own", async () => {
    const alphaMonitor = monitorIn(alpha.tenant.id, sslLabsMonitor);

    const result = await runMonitorCheck(alphaMonitor);

    expect(result.sslLabsGrade).toBe("B");
    expect(sslLabsApi).toHaveBeenCalledTimes(1);
    expect(String(sslLabsApi.mock.calls[0][0])).toContain(`host=${host}`);
  });
});

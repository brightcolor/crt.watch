import { removeDatabase } from "./support/isolatedDatabase.js";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/* Every step of the scheduler, and every monitor and organization within a
   step, fails on its own: the failure is logged with a reference and the next
   step, and the remaining work goes on. */

const work = vi.hoisted(() => ({
  failingDomains: new Set<string>(),
  failingBackupKeep: 0,
  failingMonitors: new Set<string>(),
  autoBackupFailure: null as Error | null,
  backups: [] as number[],
  autoBackups: 0,
  checked: [] as string[]
}));

vi.mock("../apps/api/src/checks/discovery.js", () => ({
  discoverMonitors: async (domain: string) => {
    if (work.failingDomains.has(domain)) throw new Error(`The resolver refused ${domain}.`);
    return [{ name: `${domain} HTTPS`, host: domain, port: 443, type: "https", tags: ["discovered"] }];
  }
}));

vi.mock("../apps/api/src/backup/backupService.js", () => ({
  backupDir: "/data/backups",
  createBackup: (settings: { keep: number }) => {
    if (settings.keep === work.failingBackupKeep) throw new Error("ENOSPC: no space left on device, copyfile");
    work.backups.push(settings.keep);
    return { name: "crtwatch-20261005-120000.sqlite" };
  },
  createAutoBackup: () => {
    if (work.autoBackupFailure) throw work.autoBackupFailure;
    work.autoBackups += 1;
    return "crtwatch-auto-20261005-120000.sqlite";
  },
  newestAutoBackupAt: () => null
}));

vi.mock("../apps/api/src/checks/monitorRunner.js", () => ({
  runMonitorCheck: async (monitor: { id: string; name: string }) => {
    if (work.failingMonitors.has(monitor.id)) throw new Error(`The check of ${monitor.name} broke.`);
    work.checked.push(monitor.id);
    return {
      id: `result-${monitor.id}-${work.checked.length}`,
      monitorId: monitor.id,
      status: "OK",
      severity: "info",
      message: "Certificate and TLS configuration look healthy.",
      checkedAt: new Date().toISOString(),
      durationMs: 5,
      daysRemaining: 60,
      validFrom: null,
      validUntil: null,
      commonName: null,
      subjectAltNames: [],
      issuer: null,
      serialNumber: null,
      fingerprintSha256: null,
      tlsVersion: null,
      cipherSuite: null,
      tlsGrade: null,
      tlsScore: null,
      sslLabsGrade: null,
      sslLabsScore: null,
      sslLabsStatus: null,
      sslLabsUrl: null,
      sslLabsCheckedAt: null,
      chain: [],
      problems: [],
      rawError: null
    };
  }
}));

import { env } from "../apps/api/src/config/env.js";
import { runScheduledWork, startScheduler } from "../apps/api/src/scheduler/scheduler.js";
import { migrate } from "../apps/api/src/storage/db.js";
import { appSettings, monitors } from "../apps/api/src/storage/repositories.js";
import { monitorIn, organization } from "./support/fixtures.js";

type Logged = { summary: string; reference: string; nextStep: string; error: unknown };

let log: ReturnType<typeof vi.spyOn>;
const logged = (): Logged[] => log.mock.calls.map((call: unknown[]) => ({ summary: String(call[1]), reference: String(call[2]), nextStep: String(call[3]), error: call[4] }));

const defaults = { schedulerIntervalSeconds: env.schedulerIntervalSeconds, autoBackupEnabled: env.autoBackupEnabled };

beforeAll(() => {
  migrate();
});

beforeEach(() => {
  log = vi.spyOn(console, "error").mockImplementation(() => {});
  work.failingDomains.clear();
  work.failingMonitors.clear();
  work.failingBackupKeep = 0;
  work.autoBackupFailure = null;
  work.backups.length = 0;
  work.autoBackups = 0;
  work.checked.length = 0;
  // Only the organizations of a test are due.
  for (const tenantId of new Set(monitors.listAll().map((monitor) => monitor.tenantId))) {
    for (const monitor of monitors.list(tenantId)) monitors.delete(monitor.id, tenantId);
  }
});

afterEach(() => {
  log.mockRestore();
  vi.useRealTimers();
  Object.assign(env, defaults);
});

afterAll(() => {
  removeDatabase();
});

describe("the scheduler", () => {
  it("runs discovery and backups for the other organizations when one of them fails", async () => {
    const failing = organization("Failing");
    const healthy = organization("Healthy");
    appSettings.set("discovery", { enabled: true, intervalHours: 24, domains: ["broken.example"], suggestions: [], lastRunAt: null }, failing.tenant.id);
    appSettings.set("discovery", { enabled: true, intervalHours: 24, domains: ["healthy.example"], suggestions: [], lastRunAt: null }, healthy.tenant.id);
    appSettings.set("backups", { enabled: true, intervalHours: 24, keep: 3, lastRunAt: null }, failing.tenant.id);
    appSettings.set("backups", { enabled: true, intervalHours: 24, keep: 4, lastRunAt: null }, healthy.tenant.id);
    work.failingDomains.add("broken.example");
    work.failingBackupKeep = 3;

    await runScheduledWork();

    expect(appSettings.discovery(failing.tenant.id).lastRunAt).toBeNull();
    expect(appSettings.discovery(healthy.tenant.id)).toMatchObject({ lastRunAt: expect.any(String), suggestions: [{ host: "healthy.example" }] });
    expect(appSettings.backups(failing.tenant.id).lastRunAt).toBeNull();
    expect(appSettings.backups(healthy.tenant.id).lastRunAt).toEqual(expect.any(String));
    expect(work.backups).toEqual([4]);
    expect(work.autoBackups).toBe(1);

    expect(logged()).toEqual([
      {
        summary: `Scheduled discovery for organization ${failing.tenant.slug} failed`,
        reference: expect.stringMatching(/^[0-9a-f]{8}$/),
        nextStep: "Check the discovery domains of the organization in Operations. crt.watch keeps running and tries again at the next scheduler run.",
        error: expect.objectContaining({ message: "The resolver refused broken.example." })
      },
      {
        summary: `The scheduled backup of organization ${failing.tenant.slug} failed`,
        reference: expect.stringMatching(/^[0-9a-f]{8}$/),
        nextStep: "Check that /data/backups is writable and has free space. crt.watch keeps running and tries again at the next scheduler run.",
        error: expect.objectContaining({ message: "ENOSPC: no space left on device, copyfile" })
      }
    ]);
    appSettings.set("discovery", { enabled: false, intervalHours: 24, domains: [], suggestions: [], lastRunAt: null }, failing.tenant.id);
    appSettings.set("backups", { enabled: false, intervalHours: 24, keep: 3, lastRunAt: null }, failing.tenant.id);
    appSettings.set("backups", { enabled: false, intervalHours: 24, keep: 4, lastRunAt: null }, healthy.tenant.id);
  });

  it("checks the other due monitors when one check fails, and then runs the remaining steps", async () => {
    const { tenant } = organization("Checks");
    const broken = monitorIn(tenant.id, { name: "broken.example" });
    const working = monitorIn(tenant.id, { name: "working.example" });
    work.failingMonitors.add(broken.id);

    await runScheduledWork();

    expect(work.checked).toEqual([working.id]);
    expect(monitors.get(working.id, tenant.id)?.lastStatus).toBe("OK");
    expect(work.autoBackups).toBe(1);
    expect(logged()).toEqual([{
      summary: `Checking monitor ${broken.id} of organization ${tenant.id} failed`,
      reference: expect.stringMatching(/^[0-9a-f]{8}$/),
      nextStep: "The other monitors are checked as usual; the error below names the cause.",
      error: expect.objectContaining({ message: "The check of broken.example broke." })
    }]);
  });

  it("goes on with the next steps when the database refuses the list of due monitors", async () => {
    const due = vi.spyOn(monitors, "due").mockImplementation(() => {
      throw new Error("SQLITE_BUSY: database is locked");
    });
    work.autoBackupFailure = new Error("EACCES: permission denied, mkdir '/data/backups'");

    try {
      await expect(runScheduledWork()).resolves.toBeUndefined();
    } finally {
      due.mockRestore();
    }

    expect(logged().map(({ summary, nextStep }) => ({ summary, nextStep }))).toEqual([
      {
        summary: "Selecting the monitors that are due failed",
        nextStep: "Check that the database file is readable and writable and that its disk has free space. crt.watch keeps running and tries again at the next scheduler run."
      },
      {
        summary: "The automatic backup failed",
        nextStep: "Check that /data/backups is writable and has free space. crt.watch keeps running and tries again at the next scheduler run."
      }
    ]);
  });

  it("runs at once and then every SCHEDULER_INTERVAL_SECONDS", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    env.schedulerIntervalSeconds = 7;
    const due = vi.spyOn(monitors, "due");

    const stop = startScheduler();
    try {
      await vi.advanceTimersByTimeAsync(0);
      expect(due).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(6_999);
      expect(due).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(due).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(7_000);
      expect(due).toHaveBeenCalledTimes(3);
    } finally {
      stop();
      due.mockRestore();
    }
  });
});

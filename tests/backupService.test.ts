import { removeDatabase } from "./support/isolatedDatabase.js";
import fs from "node:fs";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { backupDir, createBackup, listBackups } from "../apps/api/src/backup/backupService.js";
import { migrate } from "../apps/api/src/storage/db.js";

/* A backup that cannot be written leaves no partial file behind and hands
   its error to the caller, which logs it (scheduler) or answers with a
   reference (request). */

beforeAll(() => {
  migrate();
});

afterEach(() => {
  vi.useRealTimers();
});

afterAll(() => {
  removeDatabase();
});

describe("database backups", () => {
  it("remove the partial copy when the file cannot be written, and report the error", () => {
    vi.useFakeTimers({ now: new Date(2026, 9, 5, 12, 0, 0), toFake: ["Date"] });
    const name = "crtwatch-20261005-120000.sqlite";
    // A directory where the backup file belongs makes the last step of the copy fail.
    fs.mkdirSync(path.join(backupDir, name), { recursive: true });

    expect(() => createBackup({ enabled: true, intervalHours: 24, keep: 5 })).toThrow();

    expect(fs.readdirSync(backupDir).filter((entry) => entry.endsWith(".tmp"))).toEqual([]);
    fs.rmSync(path.join(backupDir, name), { recursive: true, force: true });
  });

  it("are written completely when the directory accepts them", () => {
    vi.useFakeTimers({ now: new Date(2026, 9, 5, 12, 0, 1), toFake: ["Date"] });

    const backup = createBackup({ enabled: true, intervalHours: 24, keep: 5 });

    expect(backup.name).toBe("crtwatch-20261005-120001.sqlite");
    expect(listBackups().map((entry) => entry.name)).toContain(backup.name);
    expect(fs.readdirSync(backupDir).filter((entry) => entry.endsWith(".tmp"))).toEqual([]);
  });
});

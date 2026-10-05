import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertWritableDataDirectory } from "../apps/api/src/storage/dataDirectory.js";

const created: string[] = [];
const tempDirectory = () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "crtwatch-data-"));
  created.push(directory);
  return directory;
};

afterEach(() => {
  for (const directory of created.splice(0)) {
    for (const entry of fs.readdirSync(directory)) {
      const file = path.join(directory, entry);
      if (fs.statSync(file).isFile()) fs.chmodSync(file, 0o600);
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe("data directory check", () => {
  it("creates a missing data directory", () => {
    const databasePath = path.join(tempDirectory(), "nested", "crtwatch.sqlite");
    assertWritableDataDirectory(databasePath);
    expect(fs.existsSync(path.dirname(databasePath))).toBe(true);
  });

  it("explains what to do when the directory cannot be created", () => {
    const blocker = path.join(tempDirectory(), "data");
    fs.writeFileSync(blocker, "not a directory");
    expect(() => assertWritableDataDirectory(path.join(blocker, "crtwatch.sqlite"))).toThrow(/^crt\.watch cannot write to its data directory .*\((EEXIST|ENOTDIR)\)\. The database .* and its backups are kept there\./);
  });

  // Root may write anything, so the permission case only holds for a normal user.
  it.skipIf(process.getuid?.() === 0)("names the user and the command when the database file is read-only", () => {
    const databasePath = path.join(tempDirectory(), "crtwatch.sqlite");
    fs.writeFileSync(databasePath, "");
    fs.chmodSync(databasePath, 0o444);
    const uid = process.getuid?.();
    const expected = uid === undefined ? /Then start crt\.watch again\.$/ : new RegExp(`crt\\.watch runs as uid ${uid}.*sudo chown -R ${uid}:`);
    expect(() => assertWritableDataDirectory(databasePath)).toThrow(expected);
  });
});

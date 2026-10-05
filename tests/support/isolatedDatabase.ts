import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/* Import this module first in a test file that needs a database of its own.
   It points DATABASE_PATH at a fresh file before the configuration is read, so
   the file's organizations, users and settings cannot meet those of other
   test files that run in parallel. */

export const databaseDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "crtwatch-test-"));
process.env.DATABASE_PATH = path.join(databaseDirectory, "crtwatch.sqlite");

/** Best effort: Windows keeps the open database file locked until the worker exits. */
export const removeDatabase = () => {
  try {
    fs.rmSync(databaseDirectory, { recursive: true, force: true });
  } catch {
    // The temporary directory is left for the system to clean up.
  }
};

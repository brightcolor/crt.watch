import fs from "node:fs";
import path from "node:path";
import { env } from "../config/env.js";
import { db } from "../storage/db.js";
import type { BackupSettings } from "../types.js";

export const backupDir = path.join(path.dirname(env.databasePath), "backups");
const backupName = /^crtwatch-(auto-)?\d{8}-\d{6}\.sqlite$/;

export const listBackups = () => {
  fs.mkdirSync(backupDir, { recursive: true });
  return fs.readdirSync(backupDir)
    .filter((name) => backupName.test(name))
    .map((name) => {
      const fullPath = path.join(backupDir, name);
      const stat = fs.statSync(fullPath);
      return { name, size: stat.size, createdAt: stat.birthtime.toISOString(), automatic: name.startsWith("crtwatch-auto-") };
    })
    .sort((a, b) => b.name.localeCompare(a.name));
};

export const createBackup = (settings: BackupSettings) => {
  const name = writeBackupFile(`crtwatch-${stamp(new Date())}.sqlite`);
  pruneBackups(settings.keep, (backup) => !backup.automatic);
  return listBackups().find((backup) => backup.name === name)!;
};

// Safety-net backup that runs independently of tenant-stored settings, so a
// wiped database cannot also disable the schedule that would have protected it.
export const createAutoBackup = (keep: number) => {
  const name = writeBackupFile(`crtwatch-auto-${stamp(new Date())}.sqlite`);
  pruneBackups(keep, (backup) => backup.automatic);
  return name;
};

export const newestAutoBackupAt = (): string | null =>
  listBackups().find((backup) => backup.automatic)?.createdAt ?? null;

export const backupPath = (name: string) => {
  if (!backupName.test(name)) throw new Error("Invalid backup name.");
  return path.join(backupDir, name);
};

/** The path of an existing backup file, or null for an unknown or malformed name. */
export const findBackupPath = (name: string) => {
  if (!backupName.test(name)) return null;
  const target = path.join(backupDir, name);
  return fs.existsSync(target) ? target : null;
};

export const deleteBackup = (name: string) => {
  const target = backupPath(name);
  if (fs.existsSync(target)) fs.unlinkSync(target);
};

// Checkpoint the WAL first so the copied main file contains all recent
// commits, then copy via temp file + rename so a crash mid-copy never leaves
// a truncated file that looks like a valid backup. A copy that fails is
// removed, so a full disk keeps the space it has left, and the error goes to
// the caller: the scheduler logs it, a request answers with its reference.
const writeBackupFile = (name: string) => {
  fs.mkdirSync(backupDir, { recursive: true });
  db.flush();
  const target = path.join(backupDir, name);
  const tmp = `${target}.tmp`;
  try {
    fs.copyFileSync(env.databasePath, tmp);
    fs.renameSync(tmp, target);
  } catch (error) {
    try {
      fs.rmSync(tmp, { force: true });
    } catch {
      // The error of the copy is the one to report.
    }
    throw error;
  }
  return name;
};

const pruneBackups = (keep: number, matches: (backup: { automatic: boolean }) => boolean) => {
  const stale = listBackups().filter(matches).slice(Math.max(1, keep));
  for (const backup of stale) deleteBackup(backup.name);
};

const stamp = (date: Date) =>
  `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;

const pad = (value: number) => String(value).padStart(2, "0");

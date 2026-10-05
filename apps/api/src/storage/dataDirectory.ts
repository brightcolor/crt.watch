import fs from "node:fs";
import path from "node:path";

/* The database, its WAL files and the backups share one directory, which must
   be writable for the user the server runs as. The Docker image runs as the
   unprivileged user node (uid 1000), so a data directory that an older image
   filled as root has to be handed over once. Stopping here with that
   instruction is clearer than SQLite's bare "unable to open database file". */
export const assertWritableDataDirectory = (databasePath: string) => {
  const directory = path.dirname(databasePath);
  try {
    fs.mkdirSync(directory, { recursive: true });
    fs.accessSync(directory, fs.constants.W_OK);
    for (const file of [databasePath, `${databasePath}-wal`, `${databasePath}-shm`]) {
      if (fs.existsSync(file)) fs.accessSync(file, fs.constants.R_OK | fs.constants.W_OK);
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? "unknown error";
    const uid = process.getuid?.();
    const gid = process.getgid?.();
    const owner = uid === undefined ? "" : ` crt.watch runs as uid ${uid}${gid === undefined ? "" : `, gid ${gid}`}; give that user the directory, for example on the Docker host: sudo chown -R ${uid}:${gid ?? uid} <DATA_DIR from .env, by default ./data>.`;
    throw new Error(`crt.watch cannot write to its data directory ${directory} (${code}). The database ${databasePath} and its backups are kept there.${owner} Then start crt.watch again.`);
  }
};

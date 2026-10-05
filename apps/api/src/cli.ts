import { env } from "./config/env.js";

/* Commands for the operator, run inside the container:

     docker compose exec crt-watch node apps/api/dist/cli.js setup-code

   setup-code prints the code the first-run setup asks for. It reads the code
   the running server wrote at its start and creates one if there is none yet;
   it never starts the server or changes the database schema. */

const usage = [
  "Usage: node apps/api/dist/cli.js <command>",
  "",
  "Commands:",
  "  setup-code   print the setup code for creating the first administrator"
].join("\n");

const fail = (message: string, exitCode = 1): never => {
  console.error(message);
  return process.exit(exitCode);
};

const [command] = process.argv.slice(2);

if (command !== "setup-code") {
  fail(command ? `Unknown command "${command}".\n\n${usage}` : usage, 2);
}

try {
  const { currentSetupCode, issueSetupCode, setupPath, setupRequired } = await import("./auth/setup.js");
  if (!setupRequired()) {
    fail(`The setup of this crt.watch instance is complete, so there is no setup code. Sign in at ${env.baseUrl.replace(/\/$/, "")}/login, or ask an administrator for an account.`);
  }
  const code = currentSetupCode() ?? issueSetupCode();
  console.log(`Setup code: ${code}`);
  console.log(`Open ${env.baseUrl.replace(/\/$/, "")}${setupPath} and enter it to create the first administrator.`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  if (/no such table/i.test(message)) {
    fail(`The database ${env.databasePath} has no tables yet. Start crt.watch once; it creates the database and writes the setup code to its log.`);
  }
  fail(`The setup code could not be read from ${env.databasePath}: ${message}. Check that DATABASE_PATH points at the database of the running server.`);
}

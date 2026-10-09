import { randomUUID } from "node:crypto";

/* Failures that people only learn about from the server log: errors of a
   request, which the client sees as a reference, and failures of work that
   runs in the background. Every entry carries a short reference, so an answer
   or a report leads straight to it, and says what happens next. The error
   follows as its own argument, so the log shows its stack. */

export type FailureLog = (...values: unknown[]) => void;

/** A short random reference that ties an answer or a report to its entry in the server log. */
export const errorReference = () => randomUUID().slice(0, 8);

/** Writes the failure to the server log under a fresh reference and returns the reference. */
export const logFailure = (summary: string, error: unknown, nextStep = "", log: FailureLog = console.error) => {
  const reference = errorReference();
  if (nextStep) log("%s (reference %s). %s", summary, reference, nextStep, error);
  else log("%s (reference %s):", summary, reference, error);
  return reference;
};

/** Last resort for a rejected promise that no code handles: it is logged, and crt.watch keeps running. */
export const reportUnhandledRejection = (reason: unknown, log: FailureLog = console.error) =>
  logFailure("An operation failed without an error handler", reason, "crt.watch keeps running; the error below names the operation.", log);

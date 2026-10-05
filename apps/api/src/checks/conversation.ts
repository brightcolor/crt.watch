import type net from "node:net";
import { env } from "../config/env.js";

/* A check talks to its service over the connections it opens: the TLS
   handshake, the STARTTLS negotiation, the banner, the login and the probes of
   the intensive TLS assessment. Three limits end such a conversation:

   - the monitor's timeout, when the service sends nothing for that long;
   - MONITOR_PROTOCOL_READ_LIMIT_KB, when the service sends more than that
     during one STARTTLS negotiation, banner or login;
   - MONITOR_CHECK_DEADLINE_SECONDS, when the connections of one check have been
     open that long together, however steadily the service keeps sending.

   A check creates its limits once with checkLimits() and hands them to every
   connection it opens, so all of them share one deadline. */

export type CheckLimits = {
  /** Bytes that one STARTTLS negotiation, banner or login may read. */
  readLimitBytes: number;
  /** Seconds that the connections of one check may stay open together. */
  deadlineSeconds: number;
  /** Aborts when the deadline has passed. */
  signal: AbortSignal;
};

export const checkLimits = (readLimitKb = env.monitorProtocolReadLimitKb, deadlineSeconds = env.monitorCheckDeadlineSeconds): CheckLimits => ({
  readLimitBytes: readLimitKb * 1024,
  deadlineSeconds,
  signal: AbortSignal.timeout(Math.round(deadlineSeconds * 1000))
});

/** Runs end once the deadline of the check has passed and returns the function that cancels this. */
export const onDeadline = (limits: CheckLimits, end: () => void) => {
  if (limits.signal.aborted) {
    const immediate = setImmediate(end);
    return () => clearImmediate(immediate);
  }
  limits.signal.addEventListener("abort", end, { once: true });
  return () => limits.signal.removeEventListener("abort", end);
};

const count = (value: number, unit: string) => `${value} ${unit}${value === 1 ? "" : "s"}`;
const operator = "the operator of this crt.watch instance";

export const readLimitExceeded = (activity: string, limits: Pick<CheckLimits, "readLimitBytes">) =>
  new Error(`The server sent more than ${limits.readLimitBytes / 1024} KB during the ${activity}, the most a check reads. Check that the monitor uses the right port and protocol, or ask ${operator} to raise MONITOR_PROTOCOL_READ_LIMIT_KB.`);

export const deadlinePassed = (activity: string, limits: Pick<CheckLimits, "deadlineSeconds">) =>
  new Error(`The ${activity} did not finish within the ${count(limits.deadlineSeconds, "second")} a check may take. Check that the server answers promptly, or ask ${operator} to raise MONITOR_CHECK_DEADLINE_SECONDS.`);

export const noAnswer = (activity: string, idleSeconds: number) =>
  new Error(`The ${activity} got no answer for ${count(idleSeconds, "second")}. Check that the service is reachable on this port, or raise the timeout of the monitor.`);

export const closedEarly = (activity: string) =>
  new Error(`The server closed the connection during the ${activity}. Check that the monitor uses the right port and protocol.`);

/**
 * Reads what a service sends on one connection of a check, as lines or as
 * text, within the limits of the check. The owner of the connection opens and
 * closes it; release() hands it back, for example for the TLS handshake that
 * follows STARTTLS.
 */
export class ServiceConversation {
  /** The lines read so far, in order. */
  readonly transcript: string[] = [];
  private text = "";
  private partial = "";
  private bytes = 0;
  private lines: string[] = [];
  private waiters: Array<() => void> = [];
  private failure: Error | null = null;
  private ended = false;
  private readonly stopDeadline: () => void;

  /**
   * @param activity what the conversation does, for messages: "SMTP STARTTLS negotiation"
   * @param idleSeconds the idle timeout set on the socket, for messages
   */
  constructor(
    private readonly socket: net.Socket,
    private readonly activity: string,
    private readonly limits: CheckLimits,
    private readonly idleSeconds: number
  ) {
    socket.on("data", this.onData);
    socket.on("error", this.onError);
    socket.on("timeout", this.onTimeout);
    socket.on("end", this.onEnd);
    this.stopDeadline = onDeadline(limits, () => this.fail(deadlinePassed(activity, limits)));
  }

  write(line: string) {
    this.socket.write(`${line}\r\n`);
  }

  /** The lines of one answer: reads lines until done accepts the lines read in this call. */
  async readUntil(done: (lines: string[]) => boolean): Promise<string[]> {
    const read: string[] = [];
    while (true) {
      while (this.lines.length) {
        const line = this.lines.shift()!;
        read.push(line);
        this.transcript.push(line);
        if (done(read)) return read;
      }
      if (this.failure) throw this.failure;
      if (this.ended) throw closedEarly(this.activity);
      await this.nextEvent();
    }
  }

  /** The first line that matches; the lines before it are skipped. */
  async readLine(matches: (line: string) => boolean): Promise<string> {
    const read = await this.readUntil((lines) => matches(lines[lines.length - 1]));
    return read[read.length - 1];
  }

  /** Everything the service sent, as soon as done accepts it or the service closes the connection. */
  async readText(done: (text: string) => boolean): Promise<string> {
    while (true) {
      if (done(this.text)) return this.text;
      if (this.failure) throw this.failure;
      if (this.ended) return this.text;
      await this.nextEvent();
    }
  }

  /** Stops reading; the connection stays open for its owner. */
  release() {
    this.socket.off("data", this.onData);
    this.socket.off("error", this.onError);
    this.socket.off("timeout", this.onTimeout);
    this.socket.off("end", this.onEnd);
    this.stopDeadline();
  }

  private nextEvent() {
    return new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  private wake() {
    for (const waiter of this.waiters.splice(0)) waiter();
  }

  private fail(error: Error) {
    this.failure ??= error;
    this.wake();
  }

  private onData = (chunk: Buffer | string) => {
    if (this.failure) return;
    this.bytes += Buffer.byteLength(chunk);
    if (this.bytes > this.limits.readLimitBytes) return this.fail(readLimitExceeded(this.activity, this.limits));
    const text = chunk.toString();
    this.text += text;
    const parts = (this.partial + text).split(/\r?\n/);
    this.partial = parts.pop() ?? "";
    this.lines.push(...parts.filter((line) => line.length > 0));
    this.wake();
  };

  private onError = (error: Error) => this.fail(error);

  private onTimeout = () => this.fail(noAnswer(this.activity, this.idleSeconds));

  private onEnd = () => {
    this.ended = true;
    this.wake();
  };
}

import { z } from "zod";
import { env } from "../config/env.js";
import { validateHost, validatePort } from "../checks/validation.js";
import type { Monitor } from "../types.js";

export const monitorTypes = ["https", "tls", "smtps", "imaps", "pop3s", "ldaps", "ftps", "xmpps", "smtp_starttls", "imap_starttls", "pop3_starttls", "ftp_starttls", "http", "tcp", "dns", "http_login", "ssh", "ftp", "smtp", "imap", "pop3"] as const;

// A value the check refuses becomes a validation issue with the check's message,
// so safeParse reports it and the request is answered with 400 and the reason.
const checkedBy = <T, R>(validate: (value: T) => R) => (value: T, context: z.RefinementCtx) => {
  try {
    return validate(value);
  } catch (error) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: error instanceof Error ? error.message : String(error) });
    return z.NEVER;
  }
};

export const monitorInputSchema = z.object({
  name: z.string().trim().min(1).max(120),
  host: z.string().transform(checkedBy(validateHost)),
  port: z.number().int().transform(checkedBy(validatePort)),
  type: z.enum(monitorTypes),
  enabled: z.boolean().default(true),
  intervalSeconds: z.number().int().min(60).max(2_592_000).default(env.defaultIntervalSeconds),
  timeoutSeconds: z.number().int().min(2).max(120).default(10),
  warningDays: z.number().int().min(1).max(3650).default(env.defaultWarningDays),
  criticalDays: z.number().int().min(0).max(3650).default(env.defaultCriticalDays),
  gracePeriodSeconds: z.number().int().min(0).max(604_800).default(0),
  sniEnabled: z.boolean().default(true),
  sniHost: z.string().trim().optional().nullable(),
  validateCertificate: z.boolean().default(true),
  allowSelfSigned: z.boolean().default(false),
  tags: z.array(z.string().trim().min(1).max(40)).default([]),
  notes: z.string().max(2000).optional().nullable(),
  owner: z.string().max(120).optional().nullable(),
  notificationChannelIds: z.array(z.string().uuid()).default([]),
  notificationRecipients: z.record(z.string().max(2000)).default({}),
  config: z.record(z.unknown()).default({}),
  maintenanceWindows: z.string().max(1000).optional().nullable()
});

export const defaultsFor = (partial: Partial<Monitor>) => ({
  name: partial.name ?? partial.host ?? "New monitor",
  host: partial.host ?? "",
  port: partial.port ?? 443,
  type: partial.type ?? "https",
  enabled: partial.enabled ?? true,
  intervalSeconds: partial.intervalSeconds ?? env.defaultIntervalSeconds,
  timeoutSeconds: partial.timeoutSeconds ?? 10,
  warningDays: partial.warningDays ?? env.defaultWarningDays,
  criticalDays: partial.criticalDays ?? env.defaultCriticalDays,
  gracePeriodSeconds: partial.gracePeriodSeconds ?? 0,
  sniEnabled: partial.sniEnabled ?? true,
  sniHost: partial.sniHost ?? null,
  validateCertificate: partial.validateCertificate ?? true,
  allowSelfSigned: partial.allowSelfSigned ?? false,
  tags: partial.tags ?? [],
  notes: partial.notes ?? null,
  owner: partial.owner ?? null,
  notificationChannelIds: partial.notificationChannelIds ?? [],
  notificationRecipients: partial.notificationRecipients ?? {},
  config: partial.config ?? {},
  maintenanceWindows: partial.maintenanceWindows ?? null
});

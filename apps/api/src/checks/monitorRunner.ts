import type { CheckResult, Monitor } from "../types.js";
import { appSettings, results } from "../storage/repositories.js";
import { applyResultWatches } from "./changeWatch.js";
import { enrichWithDnsResolution } from "./dnsResolution.js";
import { enrichWithSslLabs } from "./sslLabs.js";
import { markFlapping } from "./flapping.js";
import { isServiceMonitor, runServiceCheck } from "./serviceChecker.js";
import { runTlsCheck } from "./tlsChecker.js";

export const runMonitorCheck = async (monitor: Monitor, previous?: CheckResult) => {
  const tlsPolicy = appSettings.tlsPolicy(monitor.tenantId);
  const checked = isServiceMonitor(monitor.type)
    ? await runServiceCheck(monitor, previous?.fingerprintSha256, tlsPolicy)
    : await runTlsCheck(monitor, previous?.fingerprintSha256, tlsPolicy);
  const sslLabs = await enrichWithSslLabs(monitor, checked, previous, appSettings.sslLabs(monitor.tenantId), results.latestSslLabsForHost(monitor.host, monitor.tenantId));
  const dns = await enrichWithDnsResolution(monitor, sslLabs, previous);
  const alerting = appSettings.alerting(monitor.tenantId);
  const watched = applyResultWatches(dns, previous, alerting, monitor, tlsPolicy);
  return markFlapping(watched, results.listRecent(monitor.id, 10), alerting.flappingThreshold);
};

import { afterEach, describe, expect, it, vi } from "vitest";
import { booleanSetting, choiceSetting, cspSourceListSetting, integerSetting, networkListSetting } from "../apps/api/src/config/env.js";

/** Reads the configuration again with these variables set, as a start of crt.watch would. */
const startWith = async (values: Record<string, string>) => {
  vi.resetModules();
  const previous = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  Object.assign(process.env, values);
  try {
    return (await import("../apps/api/src/config/env.js")).env;
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
};

describe("monitor target settings", () => {
  afterEach(() => {
    vi.resetModules();
  });

  it("start with their defaults and read other values", async () => {
    const defaults = await startWith({});
    const custom = await startWith({ ALLOW_PRIVATE_TARGETS: "on", MONITOR_ALLOWED_NETWORKS: "10.20.0.0/16, 192.168.7.5", MONITOR_MAX_REDIRECTS: "0", MONITOR_HTTP_BODY_LIMIT_KB: "64" });
    expect(defaults).toMatchObject({ allowPrivateTargets: false, monitorAllowedNetworks: [], monitorMaxRedirects: 20, monitorHttpBodyLimitKb: 1024 });
    expect(custom).toMatchObject({
      allowPrivateTargets: true,
      monitorAllowedNetworks: [{ address: "10.20.0.0", prefix: 16, type: "ipv4" }, { address: "192.168.7.5", prefix: 32, type: "ipv4" }],
      monitorMaxRedirects: 0,
      monitorHttpBodyLimitKb: 64
    });
  });

  it("stop the start with a message that names the variable", async () => {
    await expect(startWith({ ALLOW_PRIVATE_TARGETS: "maybe" })).rejects.toThrow(/ALLOW_PRIVATE_TARGETS must be true or false, but is set to "maybe"/);
    await expect(startWith({ MONITOR_ALLOWED_NETWORKS: "intranet.local" })).rejects.toThrow(/MONITOR_ALLOWED_NETWORKS contains "intranet.local"/);
    await expect(startWith({ MONITOR_MAX_REDIRECTS: "21" })).rejects.toThrow(/MONITOR_MAX_REDIRECTS must be a whole number from 0 to 20.*default of 20/);
    await expect(startWith({ MONITOR_HTTP_BODY_LIMIT_KB: "0" })).rejects.toThrow(/MONITOR_HTTP_BODY_LIMIT_KB must be a whole number from 1 to 65536.*default of 1024/);
  });
});

describe("validated settings", () => {
  it("use the default when a variable is unset or empty", () => {
    expect(integerSetting({}, "NOTIFICATION_MAX_REDIRECTS", 3, 0, 10)).toBe(3);
    expect(integerSetting({ NOTIFICATION_MAX_REDIRECTS: " " }, "NOTIFICATION_MAX_REDIRECTS", 3, 0, 10)).toBe(3);
    expect(booleanSetting({}, "ALLOW_PRIVATE_NOTIFICATION_TARGETS", false)).toBe(false);
    expect(choiceSetting({}, "CONTENT_SECURITY_POLICY", "enforce", ["enforce", "report-only"] as const)).toBe("enforce");
    expect(networkListSetting({}, "NOTIFICATION_ALLOWED_NETWORKS")).toEqual([]);
  });

  it("read values inside their range", () => {
    expect(integerSetting({ X: "0" }, "X", 3, 0, 10)).toBe(0);
    expect(integerSetting({ X: " 10 " }, "X", 3, 0, 10)).toBe(10);
    expect(booleanSetting({ X: "YES" }, "X", false)).toBe(true);
    expect(booleanSetting({ X: "off" }, "X", true)).toBe(false);
    expect(choiceSetting({ X: "Report-Only" }, "X", "enforce", ["enforce", "report-only"] as const)).toBe("report-only");
    expect(networkListSetting({ X: "10.0.0.0/8" }, "X")).toEqual([{ address: "10.0.0.0", prefix: 8, type: "ipv4" }]);
  });

  it("stop with a message that names the variable, the accepted values and the default", () => {
    expect(() => integerSetting({ RATE_LIMIT_MAX_REQUESTS: "lots" }, "RATE_LIMIT_MAX_REQUESTS", 1200, 0, 100_000)).toThrow(
      'RATE_LIMIT_MAX_REQUESTS must be a whole number from 0 to 100000, but is set to "lots". Correct it in the environment (for example in .env) or remove it to use the default of 1200.'
    );
    expect(() => integerSetting({ X: "11" }, "X", 3, 0, 10)).toThrow(/from 0 to 10/);
    expect(() => integerSetting({ X: "-1" }, "X", 3, 0, 10)).toThrow(/from 0 to 10/);
    expect(() => integerSetting({ X: "2.5" }, "X", 3, 0, 10)).toThrow(/whole number/);
    expect(() => booleanSetting({ ALLOW_PRIVATE_NOTIFICATION_TARGETS: "ture" }, "ALLOW_PRIVATE_NOTIFICATION_TARGETS", false)).toThrow(/must be true or false, but is set to "ture"/);
    expect(() => choiceSetting({ CONTENT_SECURITY_POLICY: "off" }, "CONTENT_SECURITY_POLICY", "enforce", ["enforce", "report-only"] as const)).toThrow(/must be one of enforce, report-only.*default of enforce/);
  });

  it("read Content Security Policy sources and accept keywords without quotes", () => {
    expect(cspSourceListSetting({}, "X", ["'self'"])).toEqual(["'self'"]);
    expect(cspSourceListSetting({ X: "self data: https: https://logos.example.com *.cdn.example.com" }, "X", [])).toEqual([
      "'self'", "data:", "https:", "https://logos.example.com", "*.cdn.example.com"
    ]);
    expect(() => cspSourceListSetting({ X: "https: 'unsafe-inline'" }, "X", [])).toThrow(/"'unsafe-inline'", which is not a Content Security Policy source/);
    expect(() => cspSourceListSetting({ X: "https:;script-src" }, "X", [])).toThrow(/not a Content Security Policy source/);
  });
});

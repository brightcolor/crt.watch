import { removeDatabase } from "./support/isolatedDatabase.js";
import express, { Router, type Express } from "express";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

/* Errors of async handlers reach the error middleware: the answer is JSON
   with a reference that the server log carries, and the server keeps
   serving. Requests that crt.watch refuses get their status and the reason. */

const engine = vi.hoisted(() => ({ failure: new Error("The check engine stopped unexpectedly.") }));
vi.mock("../apps/api/src/checks/monitorRunner.js", () => ({
  runMonitorCheck: async () => {
    throw engine.failure;
  }
}));

import { attachSession } from "../apps/api/src/auth/auth.js";
import { errorHandler, forwardRejections, forwardsRejections, refusal } from "../apps/api/src/routes/errors.js";
import { apiRoutes } from "../apps/api/src/routes/index.js";
import { publicRoutes } from "../apps/api/src/routes/publicRoutes.js";
import { migrate } from "../apps/api/src/storage/db.js";
import { reportUnhandledRejection } from "../apps/api/src/utils/failures.js";
import { monitorIn, organization } from "./support/fixtures.js";
import { readCookies, serve } from "./support/http.js";

type Client = Awaited<ReturnType<typeof serve>>;

const clients: Client[] = [];
const start = async (app: Express) => {
  const client = await serve(app);
  clients.push(client);
  return client;
};

const appWith = (router: Router, setup: (app: Express) => void = () => {}) => {
  const app = express();
  setup(app);
  app.use(router);
  app.use(errorHandler);
  return app;
};

const referenceIn = (message: string) => /reference ([0-9a-f]{8}) in the server log/.exec(message)?.[1];

/** The reference of each failure the server log received, with its summary. */
const loggedFailures = (log: ReturnType<typeof vi.spyOn>) =>
  log.mock.calls.map((call: unknown[]) => ({ summary: String(call[1]), reference: String(call[2]) }));

let log: ReturnType<typeof vi.spyOn>;

beforeAll(() => {
  migrate();
});

afterEach(async () => {
  await Promise.all(clients.splice(0).map((client) => client.close()));
  log?.mockRestore();
});

afterAll(() => {
  removeDatabase();
});

describe("a rejected promise of a handler", () => {
  it("reaches the error middleware, which answers 500 with the reference of its log entry", async () => {
    log = vi.spyOn(console, "error").mockImplementation(() => {});
    const router = Router();
    router.get("/report", async () => {
      throw new Error("The report store is unavailable.");
    });
    const { call } = await start(appWith(forwardRejections(router)));

    const answer = await call("GET", "/report?token=kept-out-of-the-log");

    expect(answer.status).toBe(500);
    const reference = referenceIn(answer.json().error);
    expect(answer.json().error).toBe(`crt.watch could not complete this request because of an error on the server. Try again; if it keeps failing, ask the operator to look up reference ${reference} in the server log.`);
    expect(loggedFailures(log)).toEqual([{ summary: "Request GET /report failed", reference }]);
    expect(log.mock.calls[0][3]).toMatchObject({ message: "The report store is unavailable." });
  });

  it("of middleware, of a nested router and of error middleware reaches it as well", async () => {
    log = vi.spyOn(console, "error").mockImplementation(() => {});
    const inner = Router();
    inner.get("/route", async () => {
      throw new Error("inner route");
    });
    const handling = Router();
    handling.get("/route", async () => {
      throw new Error("first failure");
    });
    handling.use(async (error: Error, _req: express.Request, _res: express.Response, _next: express.NextFunction) => {
      throw new Error(`error middleware failed while handling: ${error.message}`);
    });
    const outer = Router();
    outer.use("/guarded", async () => {
      throw new Error("middleware");
    });
    outer.use("/inner", inner);
    outer.use("/handling", handling);
    const { call } = await start(appWith(forwardRejections(outer)));

    for (const path of ["/guarded/anything", "/inner/route", "/handling/route"]) {
      const answer = await call("GET", path);
      expect(answer.status, path).toBe(500);
      expect(referenceIn(answer.json().error), path).toMatch(/^[0-9a-f]{8}$/);
    }
    expect(log.mock.calls.map((call: unknown[]) => (call[3] as Error).message)).toEqual([
      "middleware",
      "inner route",
      "error middleware failed while handling: first failure"
    ]);
  });

  it("with a reason that is no Error reaches it as well", async () => {
    log = vi.spyOn(console, "error").mockImplementation(() => {});
    const router = Router();
    router.get("/text", () => Promise.reject("the queue is closed"));
    const { call } = await start(appWith(forwardRejections(router)));

    const answer = await call("GET", "/text");

    expect(answer.status).toBe(500);
    expect((log.mock.calls[0][3] as Error).message).toBe("A request handler failed with: the queue is closed");
  });

  it("closes the connection when the answer has begun, and the server keeps answering", async () => {
    log = vi.spyOn(console, "error").mockImplementation(() => {});
    const router = Router();
    router.get("/stream", async (_req, res) => {
      res.write("first part");
      await new Promise((resolve) => setTimeout(resolve, 20));
      throw new Error("The stream source failed.");
    });
    router.get("/health", (_req, res) => res.json({ ok: true }));
    const { base, call } = await start(appWith(forwardRejections(router)));

    const response = await fetch(`${base}/stream`);
    await expect(response.text()).rejects.toThrow();

    expect((await call("GET", "/health")).json()).toEqual({ ok: true });
    expect(loggedFailures(log)).toEqual([{ summary: "Request GET /stream failed", reference: expect.stringMatching(/^[0-9a-f]{8}$/) }]);
  });

  it("is forwarded by every handler below /api and /public", () => {
    type Layer = { name: string; handle: (...args: never[]) => unknown; route?: { path: string; stack: Layer[] } };
    const handlers = (router: { stack: Layer[] }): Array<{ where: string; handle: Layer["handle"] }> => router.stack.flatMap((layer) => {
      if (layer.route) return layer.route.stack.map((step) => ({ where: layer.route!.path, handle: step.handle }));
      const nested = layer.handle as unknown as { stack?: Layer[] };
      return Array.isArray(nested.stack) ? handlers(nested as { stack: Layer[] }) : [{ where: layer.name, handle: layer.handle }];
    });

    const api = handlers(apiRoutes as unknown as { stack: Layer[] });
    const open = handlers(publicRoutes as unknown as { stack: Layer[] });

    expect(api.length).toBeGreaterThan(100);
    expect(open.length).toBeGreaterThanOrEqual(6);
    expect([...api, ...open].filter((entry) => !forwardsRejections(entry.handle)).map((entry) => entry.where)).toEqual([]);
  });

  it("forwarding twice wraps each handler once", () => {
    const router = Router();
    router.get("/once", async () => undefined);
    forwardRejections(forwardRejections(router));
    const layer = (router as unknown as { stack: Array<{ route: { stack: Array<{ handle: () => unknown }> } }> }).stack[0];
    const handle = layer.route.stack[0].handle;
    forwardRejections(router);
    expect(layer.route.stack[0].handle).toBe(handle);
    expect(forwardsRejections(handle)).toBe(true);
  });
});

describe("an API route whose async work fails", () => {
  it("answers 500 with a reference, and the server keeps serving", async () => {
    log = vi.spyOn(console, "error").mockImplementation(() => {});
    const { tenant, session } = organization("Engine");
    const monitor = monitorIn(tenant.id);
    const app = express();
    app.use(express.json());
    app.use(readCookies);
    app.use(attachSession);
    app.use("/api", apiRoutes);
    app.use(errorHandler);
    const { call } = await start(app);

    const failed = await call("POST", `/api/monitors/${monitor.id}/check`, {}, { session, tenantId: tenant.id });
    expect(failed.status).toBe(500);
    const reference = referenceIn(failed.json().error);
    expect(loggedFailures(log)).toEqual([{ summary: `Request POST /api/monitors/${monitor.id}/check failed`, reference }]);
    expect(log.mock.calls[0][3]).toBe(engine.failure);

    const listed = await call("GET", "/api/monitors", undefined, { session, tenantId: tenant.id });
    expect(listed.status).toBe(200);
    expect(listed.json().map((item: { id: string }) => item.id)).toContain(monitor.id);
  });
});

describe("a request that crt.watch refuses", () => {
  const jsonApp = (limit: string) => {
    const router = Router();
    router.post("/import", (req, res) => res.json({ received: Object.keys(req.body ?? {}).length }));
    return appWith(router, (app) => app.use(express.json({ limit })));
  };

  const post = (base: string, body: string) => fetch(`${base}/import`, { method: "POST", headers: { "content-type": "application/json" }, body });

  it("with a body that is not JSON answers 400 and says what to change", async () => {
    log = vi.spyOn(console, "error").mockImplementation(() => {});
    const { base } = await start(jsonApp("1mb"));

    const answer = await post(base, "{\"monitors\": [");

    expect(answer.status).toBe(400);
    expect(await answer.json()).toEqual({ error: "The request body is not valid JSON. Check its syntax and send it again." });
    expect(log).not.toHaveBeenCalled();
  });

  it("with a body over the limit answers 413 and names the limit", async () => {
    const small = await start(jsonApp("2kb"));
    const large = await start(jsonApp("1mb"));
    const body = JSON.stringify({ monitors: "x".repeat(4096) });

    const refused = await post(small.base, body);
    expect(refused.status).toBe(413);
    expect((await refused.json()).error).toBe("The request body is larger than crt.watch accepts (2 KB). Send a smaller body, for example by importing fewer monitors at once.");
    expect((await post(large.base, body)).status).toBe(200);
  });

  it("with another client error keeps its status and its reason", () => {
    expect(refusal({ status: 400, expose: true, message: "Failed to decode param '%E0%A4%A'" })).toEqual({
      status: 400,
      message: "crt.watch could not process this request (HTTP 400: Failed to decode param '%E0%A4%A'). Check the address and the request, then try again."
    });
  });

  it("is told apart from a failure on the server, which keeps its reason in the log", () => {
    // A file of the server that is missing, as sendFile reports it.
    expect(refusal({ statusCode: 404, expose: false, message: "ENOENT, stat '/srv/web/index.html'" })).toBeNull();
    expect(refusal(new Error("database is locked"))).toBeNull();
    expect(refusal({ status: 503, expose: true, message: "busy" })).toBeNull();
  });
});

describe("a rejected promise outside requests", () => {
  it("is logged with a reference, and crt.watch keeps running", () => {
    const lines: unknown[][] = [];
    const reason = new Error("The certificate feed closed.");

    const reference = reportUnhandledRejection(reason, (...values) => lines.push(values));

    expect(reference).toMatch(/^[0-9a-f]{8}$/);
    expect(lines).toEqual([["%s (reference %s). %s", "An operation failed without an error handler", reference, "crt.watch keeps running; the error below names the operation.", reason]]);
  });
});

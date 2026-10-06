import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import {
  SurfaceClient,
  SurfaceError,
  SurfaceUnavailableError,
  RateLimitError,
  ToolGuard,
  scanMiddleware,
  createSafeFetch,
} from "../src/index.js";

const SCAN_RESPONSE = {
  name: "payload.bin",
  size: 5,
  hash: "abc",
  contentType: "text/plain",
  safetyScore: {
    score: 100,
    threatLevel: "Clean",
    confidence: "High",
    confidenceScore: 0.9,
    confidenceReason: "",
    primaryThreat: "",
    threatSummary: "",
    enginesUsed: [],
    recommendedAction: "Allow",
    coverage: "full",
  },
  scanTimeMs: 1,
  timestamp: 0,
};

type Handler = (req: IncomingMessage, res: ServerResponse, body: string) => void;

/**
 * A local fake Surface: each request takes the next handler, the last one
 * repeats. Records each request body so retries can be checked.
 */
async function fakeSurface(handlers: Handler[]) {
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      bodies.push(body);
      handlers[Math.min(bodies.length - 1, handlers.length - 1)](req, res, body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url,
    bodies,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

const json =
  (status: number, body: unknown, headers: Record<string, string> = {}): Handler =>
  (_req, res) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  };
const ok = json(200, SCAN_RESPONSE);
const hang: Handler = () => {};

/** A client against `url` with a short budget and retry waits in 10 ms units. */
function client(url: string, timeoutMs = 2000, mode: "api" | "local" = "api"): SurfaceClient {
  const c = new SurfaceClient(
    mode === "api" ? { apiKey: "sfk_test", baseUrl: url, timeoutMs } : { mode, scannerUrl: url, timeoutMs },
  );
  c.retryUnitMs = 10;
  return c;
}

test("default timeout is 60 s; a non-positive one is refused", () => {
  const c = new SurfaceClient({ apiKey: "sfk_test" }) as unknown as { timeoutMs: number };
  assert.equal(c.timeoutMs, 60_000);
  assert.throws(() => new SurfaceClient({ apiKey: "sfk_test", timeoutMs: 0 }), SurfaceError);
});

test("connection refused throws SurfaceUnavailableError within the budget", async () => {
  const srv = await fakeSurface([ok]);
  const url = srv.url;
  await srv.close(); // nothing listens on the port now
  const started = Date.now();
  await assert.rejects(client(url, 300).scanPayload("hello"), (err: unknown) => {
    assert.ok(err instanceof SurfaceUnavailableError);
    assert.equal(err.statusCode, 0);
    assert.match(err.message, /ECONNREFUSED/);
    assert.ok(err.cause);
    return true;
  });
  assert.ok(Date.now() - started < 1000);
});

test("HTTP 500 is unavailable, not retried, and carries the server's error text", async () => {
  const srv = await fakeSurface([json(500, { error: "scanner crashed" }), ok]);
  try {
    await assert.rejects(client(srv.url).scanPayload("hello"), (err: unknown) => {
      assert.ok(err instanceof SurfaceUnavailableError);
      assert.ok(err instanceof SurfaceError);
      assert.equal(err.statusCode, 500);
      assert.match(err.message, /scanner crashed/);
      return true;
    });
    assert.equal(srv.bodies.length, 1);
  } finally {
    await srv.close();
  }
});

for (const status of [502, 503, 504]) {
  test(`HTTP ${status} then success: the scan succeeds after a retry`, async () => {
    const srv = await fakeSurface([json(status, { error: "warming up" }), ok]);
    try {
      const result = await client(srv.url).scanPayload("hello");
      assert.equal((result as typeof SCAN_RESPONSE).safetyScore.threatLevel, "Clean");
      assert.equal(srv.bodies.length, 2);
      assert.equal(srv.bodies[1], srv.bodies[0]); // same request resent
    } finally {
      await srv.close();
    }
  });
}

test("a multipart file upload is rebuilt for the retry", async () => {
  const srv = await fakeSurface([json(503, {}), ok]);
  try {
    await client(srv.url).scanFile(Buffer.from("file-bytes"), { filename: "a.txt" });
    assert.equal(srv.bodies.length, 2);
    assert.match(srv.bodies[1], /file-bytes/);
  } finally {
    await srv.close();
  }
});

test("503 forever throws SurfaceUnavailableError before the budget ends", async () => {
  const srv = await fakeSurface([json(503, { error: "warming up" })]);
  const started = Date.now();
  try {
    await assert.rejects(client(srv.url, 300).scanPayload("hello"), (err: unknown) => {
      assert.ok(err instanceof SurfaceUnavailableError);
      assert.equal(err.statusCode, 503);
      assert.match(err.message, /warming up/);
      return true;
    });
    // Waits of 10, 20, 40, 80 ms...; the next one would cross 300 ms.
    assert.ok(Date.now() - started < 300);
    assert.ok(srv.bodies.length >= 4);
  } finally {
    await srv.close();
  }
});

test("at most 10 retries", async () => {
  const srv = await fakeSurface([json(503, {})]);
  const c = client(srv.url, 30_000);
  c.retryUnitMs = 1;
  try {
    await assert.rejects(c.scanPayload("hello"), SurfaceUnavailableError);
    assert.equal(srv.bodies.length, 11);
  } finally {
    await srv.close();
  }
});

test("Retry-After is honored in place of the backoff", async () => {
  const srv = await fakeSurface([json(503, {}, { "Retry-After": "5" }), ok]);
  const started = Date.now();
  try {
    await client(srv.url).scanPayload("hello");
    // Retry-After 5 s in 10 ms units; the backoff alone would wait 10 ms.
    assert.ok(Date.now() - started >= 50);
  } finally {
    await srv.close();
  }
});

test("a Retry-After that would end past the budget gives up at once", async () => {
  const srv = await fakeSurface([json(503, {}, { "Retry-After": "8" }), ok]);
  const started = Date.now();
  try {
    await assert.rejects(client(srv.url, 50).scanPayload("hello"), SurfaceUnavailableError);
    assert.equal(srv.bodies.length, 1);
    assert.ok(Date.now() - started < 50);
  } finally {
    await srv.close();
  }
});

test("a hung server throws SurfaceUnavailableError at the timeout", async () => {
  const srv = await fakeSurface([hang]);
  const started = Date.now();
  try {
    await assert.rejects(client(srv.url, 200).scanPayload("hello"), (err: unknown) => {
      assert.ok(err instanceof SurfaceUnavailableError);
      assert.match(err.message, /200 ms/);
      return true;
    });
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 190 && elapsed < 1000, `elapsed ${elapsed}`);
    assert.equal(srv.bodies.length, 1); // a timeout is not retried
  } finally {
    await srv.close();
  }
});

test("local mode uses the same timeout", async () => {
  const srv = await fakeSurface([hang]);
  try {
    await assert.rejects(client(srv.url, 100, "local").scanPayload("hello"), SurfaceUnavailableError);
  } finally {
    await srv.close();
  }
});

test("non-scan calls use the same budget and retries", async () => {
  const usage = { scans_used: 1, max_scans: 10, scans_remaining: 9, max_file_size_mb: 10, plan_tier: "free", reset_at: "2026-11-01" };
  const srv = await fakeSurface([json(502, {}), json(200, usage)]);
  try {
    assert.equal((await client(srv.url).getUsage()).scans_used, 1);
    assert.equal(srv.bodies.length, 2);
  } finally {
    await srv.close();
  }
});

for (const status of [200, 502]) {
  test(`an HTML body on HTTP ${status} throws SurfaceUnavailableError`, async () => {
    const html: Handler = (_req, res) => {
      res.writeHead(status, { "content-type": "text/html" });
      res.end("<html><body>Bad Gateway</body></html>");
    };
    const srv = await fakeSurface([html]);
    try {
      await assert.rejects(client(srv.url, 100).scanPayload("hello"), (err: unknown) => {
        assert.ok(err instanceof SurfaceUnavailableError);
        assert.equal(err.statusCode, status);
        assert.match(err.message, /not JSON/);
        return true;
      });
    } finally {
      await srv.close();
    }
  });
}

test("429 still throws RateLimitError and is not retried", async () => {
  const srv = await fakeSurface([json(429, { error: "rate limit" }, { "Retry-After": "1" }), ok]);
  try {
    await assert.rejects(client(srv.url).scanPayload("hello"), (err: unknown) => {
      assert.ok(err instanceof RateLimitError);
      assert.ok(!(err instanceof SurfaceUnavailableError));
      return true;
    });
    assert.equal(srv.bodies.length, 1);
  } finally {
    await srv.close();
  }
});

test("ToolGuard fails closed: the tool does not run when Surface is unavailable", async () => {
  const srv = await fakeSurface([json(500, { error: "down" })]);
  let ran = false;
  try {
    const guard = new ToolGuard(client(srv.url));
    const tool = guard.wrap(async (_args: unknown) => {
      ran = true;
    }, "delete_file");
    await assert.rejects(tool({ path: "/tmp/x" }), SurfaceUnavailableError);
    await assert.rejects(guard.screen("delete_file", {}), SurfaceUnavailableError);
    assert.equal(ran, false);
  } finally {
    await srv.close();
  }
});

/** Run the middleware once; "next" when it passed the request on. */
async function runMiddleware(c: SurfaceClient, failOpen?: boolean): Promise<number | "next"> {
  const mw = scanMiddleware(c, failOpen === undefined ? undefined : { failOpen });
  return new Promise((resolve) => {
    const res = {
      setHeader() {},
      status(code: number) {
        return { json: () => resolve(code) };
      },
    };
    mw({ method: "POST", body: "hello", headers: {}, path: "/x" }, res, () => resolve("next"));
  });
}

test("middleware follows failOpen on SurfaceUnavailableError", async () => {
  const srv = await fakeSurface([json(500, {})]);
  try {
    assert.equal(await runMiddleware(client(srv.url)), "next");
    assert.equal(await runMiddleware(client(srv.url), false), 503);

    const closed = createSafeFetch(client(srv.url), { failOpen: false });
    await assert.rejects(closed(srv.url, { method: "POST", body: "x" }), /security scan unavailable/);
  } finally {
    await srv.close();
  }
});

// HTTP status → error class, matched to the Surface backend's real bodies:
// quota exhaustion is 402 (not 429); ?defer=true on a plan without async
// scanning is also 402 but is a plan wall; 429 is always a rate limit; 403 is
// never an authentication error.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import {
  SurfaceClient,
  SurfaceError,
  AuthenticationError,
  PermissionDeniedError,
  PlanRequiredError,
  QuotaExceededError,
  RateLimitError,
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

async function withServer(
  status: number,
  body: unknown,
  fn: (c: SurfaceClient, urls: string[]) => Promise<void>,
) {
  const urls: string[] = [];
  const server = createServer((req, res) => {
    urls.push(req.url ?? "");
    req.resume();
    req.on("end", () => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await fn(new SurfaceClient({ apiKey: "sfk_test", baseUrl: url, timeoutMs: 2000 }), urls);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  }
}

const QUOTA_402 = { error: "monthly scan quota exceeded (100/100 scans used)", requestId: "r1" };
const DEFER_402 = {
  error: "async scanning is not included on the free plan",
  feature: "async scanning",
  current_plan: "free",
  upgrade: true,
  requestId: "r2",
};
const PLAN_403 = {
  error: "the free plan includes 1 scan profile(s); this account has 1",
  feature: "scan profiles",
  current_plan: "free",
  code: "plan_required",
  limit: 1,
  upgrade: true,
};

async function caught(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  assert.fail("expected a throw");
}

test("402 quota → QuotaExceededError", async () => {
  await withServer(402, QUOTA_402, async (c) => {
    const e = await caught(c.scanPayload("hi"));
    assert.ok(e instanceof QuotaExceededError);
    assert.equal(e.statusCode, 402);
    assert.equal(e.message, QUOTA_402.error);
    assert.ok(!(e instanceof PermissionDeniedError));
  });
});

test("402 from defer without async → PlanRequiredError, not quota", async () => {
  await withServer(402, DEFER_402, async (c) => {
    const e = await caught(c.scanFile(Buffer.from("x"), { defer: true, filename: "x.txt" }));
    assert.ok(e instanceof PlanRequiredError, String(e));
    assert.ok(!(e instanceof QuotaExceededError));
    assert.equal(e.statusCode, 402);
    assert.equal(e.feature, "async scanning");
    assert.equal(e.currentPlan, "free");
    assert.equal(e.code, undefined);
  });
});

test("402 other → generic SurfaceError", async () => {
  await withServer(402, { error: "could not verify this API key with the server" }, async (c) => {
    const e = await caught(c.scanPayload("hi"));
    assert.equal((e as Error).constructor, SurfaceError);
    assert.equal((e as SurfaceError).statusCode, 402);
  });
});

test("403 plan_required → PlanRequiredError (a PermissionDeniedError)", async () => {
  await withServer(403, PLAN_403, async (c) => {
    const e = await caught(c.getUsage());
    assert.ok(e instanceof PlanRequiredError);
    assert.ok(e instanceof PermissionDeniedError);
    assert.ok(!(e instanceof AuthenticationError));
    assert.equal(e.statusCode, 403);
    assert.equal(e.code, "plan_required");
    assert.equal(e.feature, "scan profiles");
    assert.equal(e.message, PLAN_403.error);
  });
});

for (const msg of [
  "IP address is blocked",
  "permission denied: scans:write required",
  "Payload scanning is not enabled for this scan profile. Update the profile or use an API key linked to a profile with payload scanning enabled.",
]) {
  test(`403 "${msg.slice(0, 30)}" → PermissionDeniedError, not auth`, async () => {
    await withServer(403, { error: msg }, async (c) => {
      const e = await caught(c.scanPayload("hi"));
      assert.equal((e as Error).constructor, PermissionDeniedError);
      assert.ok(!(e instanceof AuthenticationError));
      assert.equal((e as PermissionDeniedError).message, msg);
      assert.equal((e as PermissionDeniedError).statusCode, 403);
      assert.equal((e as PermissionDeniedError).code, undefined);
    });
  });
}

test("401 stays AuthenticationError", async () => {
  await withServer(401, { error: "invalid API key" }, async (c) => {
    const e = await caught(c.scanPayload("hi"));
    assert.ok(e instanceof AuthenticationError);
    assert.equal(e.statusCode, 401);
  });
});

for (const body of [
  { error: "rate limit exceeded", plan: "free", limit_per_minute: 10 },
  // No Retry-After and no "rate": still a rate limit (quota is 402).
  { error: "slow down" },
]) {
  test(`429 ${JSON.stringify(body)} → RateLimitError`, async () => {
    await withServer(429, body, async (c) => {
      const e = await caught(c.scanPayload("hi"));
      assert.ok(e instanceof RateLimitError);
      assert.ok(!(e instanceof QuotaExceededError));
      assert.equal(e.statusCode, 429);
    });
  });
}

test("scanPayload does not send ?defer=true", async () => {
  await withServer(200, SCAN_RESPONSE, async (c, urls) => {
    const res = await c.scanPayload("hi", "p.txt", { defer: true });
    assert.ok("safetyScore" in res);
    assert.ok(!urls[0].includes("defer"), urls[0]);
  });
});

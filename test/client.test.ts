import { test } from "node:test";
import assert from "node:assert/strict";

import { SurfaceClient, MaliciousFileError, type Usage } from "../src/index.js";

// A scan response whose threatLevel is capitalized, exactly as the backend emits.
const SCAN_RESPONSE = {
  name: "sample.exe",
  size: 10,
  hash: "abc123",
  contentType: "application/octet-stream",
  safetyScore: {
    score: 5,
    threatLevel: "Malicious",
    confidence: "High",
    confidenceScore: 0.95,
    confidenceReason: "",
    primaryThreat: "trojan",
    threatSummary: "",
    enginesUsed: [],
    recommendedAction: "Block",
    coverage: "full",
  },
  scanTimeMs: 1,
  timestamp: 0,
};

// A minimal-coverage response: a JAR the engines cleared, which the backend
// caps at Informational because no ML model covers JVM bytecode.
const MINIMAL_COVERAGE_RESPONSE = {
  name: "app.jar",
  size: 4096,
  hash: "def456",
  contentType: "application/java-archive",
  safetyScore: {
    score: 85,
    threatLevel: "Informational",
    confidence: "Medium",
    confidenceScore: 0.6,
    confidenceReason: "",
    primaryThreat: "No threats detected",
    threatSummary: "",
    enginesUsed: ["YARA"],
    recommendedAction: "Allow",
    coverage: "minimal",
    coverageNote: "Archive of JVM or Android bytecode.",
  },
  scanTimeMs: 1,
  timestamp: 0,
};

const USAGE_RESPONSE = {
  scans_used: 5,
  max_scans: 100,
  scans_remaining: 95,
  max_file_size_mb: 10,
  plan_tier: "free",
  reset_at: "2026-07-01",
  daily_volume: { dates: ["2026-06-15"], counts: [5] },
};

const HISTORY_RESPONSE = {
  scans: [],
  total: 0,
  page: 1,
  limit: 25,
  has_more: false,
};

interface Captured {
  url?: string;
  init?: RequestInit;
}

/** Build a client whose fetch returns `body` and records the request. */
function clientReturning(body: unknown, status = 200): { client: SurfaceClient; captured: Captured } {
  const captured: Captured = {};
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    captured.url = String(url);
    captured.init = init;
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;

  const client = new SurfaceClient({ apiKey: "sfk_test", fetch: fetchImpl });
  return { client, captured };
}

test("getUsage targets the real service base and parses backend fields", async () => {
  const { client, captured } = clientReturning(USAGE_RESPONSE);
  const usage: Usage = await client.getUsage();

  assert.equal(captured.url, "https://app.tendrl.com/surface/api/account/usage");
  assert.equal(usage.scans_used, 5);
  assert.equal(usage.max_scans, 100);
  assert.equal(usage.scans_remaining, 95);
  assert.equal(usage.max_file_size_mb, 10);
  assert.equal(usage.plan_tier, "free");
  assert.deepEqual(usage.daily_volume?.counts, [5]);
});

test("getScanHistory uses the /account/history path", async () => {
  const { client, captured } = clientReturning(HISTORY_RESPONSE);
  await client.getScanHistory({ page: 1, limit: 25 });
  assert.ok(captured.url?.includes("/api/account/history"));
  assert.ok(!captured.url?.includes("/account/scans"));
});

test("reject matches case-insensitively", async () => {
  const { client } = clientReturning(SCAN_RESPONSE);
  await assert.rejects(
    () => client.scanFile(Buffer.from("payload"), { reject: ["malicious"] }),
    MaliciousFileError,
  );
});

test("reject does not falsely match other levels", async () => {
  const { client } = clientReturning(SCAN_RESPONSE);
  const result = await client.scanFile(Buffer.from("payload"), { reject: ["clean"] });
  assert.equal((result as { safetyScore: { threatLevel: string } }).safetyScore.threatLevel, "Malicious");
});

test("requestId is sent as the X-Request-ID header, not a query param", async () => {
  const { client, captured } = clientReturning(SCAN_RESPONSE);
  await client.scanFile(Buffer.from("payload"), { requestId: "req-abc-123" });

  const headers = new Headers(captured.init?.headers);
  assert.equal(headers.get("X-Request-ID"), "req-abc-123");
  assert.ok(!captured.url?.includes("requestId"));
  assert.ok(!captured.url?.includes("request_id"));
});

test("coverage and coverageNote survive deserialization", async () => {
  const { client } = clientReturning(MINIMAL_COVERAGE_RESPONSE);
  const result = (await client.scanFile(Buffer.from("PK\x03\x04"))) as {
    safetyScore: { coverage?: string; coverageNote?: string; threatLevel: string };
  };

  assert.equal(result.safetyScore.coverage, "minimal");
  assert.ok(result.safetyScore.coverageNote);
  // A minimal scan must never claim Clean.
  assert.notEqual(result.safetyScore.threatLevel, "Clean");
});

test("a response without coverage still parses", async () => {
  // An older deployment omits the field entirely; the SDK must not reject it.
  const legacy = structuredClone(SCAN_RESPONSE) as {
    safetyScore: Record<string, unknown>;
  };
  delete legacy.safetyScore.coverage;

  const { client } = clientReturning(legacy);
  const result = (await client.scanFile(Buffer.from("payload"), {})) as {
    safetyScore: { coverage?: string };
  };
  assert.equal(result.safetyScore.coverage, undefined);
});

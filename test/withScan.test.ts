import { test } from "node:test";
import assert from "node:assert/strict";

import { SurfaceClient, withScan, MaliciousFileError } from "../src/index.js";

function scoreResponse(threatLevel: string) {
  return {
    name: "upload.bin",
    size: 5,
    hash: "abc123",
    contentType: "application/octet-stream",
    safetyScore: {
      score: threatLevel === "Malicious" ? 5 : 99,
      threatLevel,
      confidence: "High",
      confidenceScore: 0.95,
      confidenceReason: "",
      primaryThreat: threatLevel === "Malicious" ? "trojan" : "",
      threatSummary: "",
      enginesUsed: [],
      recommendedAction: threatLevel === "Malicious" ? "Block" : "Allow",
      coverage: "full",
    },
    scanTimeMs: 1,
    timestamp: 0,
  };
}

/** A real client whose fetch returns `body` — exercises the client's own reject path. */
function clientReturning(body: unknown): SurfaceClient {
  const fetchImpl = (async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof globalThis.fetch;
  return new SurfaceClient({ apiKey: "sfk_test", fetch: fetchImpl });
}

test("withScan runs the handler with the ScanResult for accepted files", async () => {
  const process = withScan(
    (result) => result.safetyScore.threatLevel,
    { client: clientReturning(scoreResponse("Clean")) },
  );

  const level = await process(Buffer.from("hello"));
  assert.equal(level, "Clean");
});

test("withScan passes extra args through to the handler", async () => {
  const process = withScan(
    (result, tag: string) => `${tag}:${result.safetyScore.threatLevel}`,
    { client: clientReturning(scoreResponse("Clean")) },
  );

  assert.equal(await process(Buffer.from("hi"), "upload"), "upload:Clean");
});

test("withScan rejects before the handler runs", async () => {
  let called = false;
  const process = withScan(
    () => {
      called = true;
    },
    { client: clientReturning(scoreResponse("Malicious")), reject: ["Malicious"] },
  );

  await assert.rejects(() => process(Buffer.from("x")), MaliciousFileError);
  assert.equal(called, false);
});

test("withScan rejects on the recommended action (Block)", async () => {
  // scoreResponse("Malicious") carries recommendedAction "Block".
  let called = false;
  const process = withScan(
    () => {
      called = true;
    },
    { client: clientReturning(scoreResponse("Malicious")), reject: ["Block"] },
  );

  await assert.rejects(() => process(Buffer.from("x")), MaliciousFileError);
  assert.equal(called, false);
});

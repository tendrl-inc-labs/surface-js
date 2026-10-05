import { test } from "node:test";
import assert from "node:assert/strict";

import { scanMiddleware } from "../src/middleware.js";

// A stand-in client: scanMiddleware only calls scanPayload.
function clientWith(threatLevel: string, recommendedAction: string): any {
  return {
    scanPayload: async () => ({ requestId: "r1", safetyScore: { threatLevel, recommendedAction, primaryThreat: "x" } }),
  };
}

async function run(threatLevel: string, recommendedAction: string): Promise<number | "next"> {
  const mw = scanMiddleware(clientWith(threatLevel, recommendedAction));
  let status: number | "next" = "next";
  const res = {
    setHeader() {},
    status(code: number) {
      status = code;
      return { json() {} };
    },
  };
  await new Promise<void>((resolve) => {
    mw({ method: "POST", body: "hello", headers: {}, path: "/x" }, res, () => resolve());
    setTimeout(resolve, 50);
  });
  return status;
}

// By default the middleware rejects whatever Surface recommends blocking,
// which includes Risky (an agent action), not only Malicious.
test("default reject is the Block recommendation", async () => {
  assert.equal(await run("Malicious", "Block"), 403);
  assert.equal(await run("Risky", "Block"), 403);
  assert.equal(await run("Suspicious", "Review"), "next");
  assert.equal(await run("Clean", "Allow"), "next");
});

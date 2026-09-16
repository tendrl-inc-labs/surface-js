import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SurfaceClient,
  ToolGuard,
  ToolBlocked,
  toolCallJson,
  type ActionContext,
  type ToolGuardOptions,
} from "../src/index.js";

function resp(action: string, opts: { primaryThreat?: string; actionScreen?: unknown } = {}) {
  const base = {
    name: "t.toolcall.json",
    size: 1,
    hash: "x",
    contentType: "application/json",
    safetyScore: {
      score: action === "Allow" ? 100 : 25,
      threatLevel: action === "Block" ? "Malicious" : action === "Review" ? "Suspicious" : "Clean",
      confidence: "High",
      confidenceScore: 0.9,
      confidenceReason: "",
      primaryThreat: opts.primaryThreat ?? "",
      threatSummary: "",
      enginesUsed: ["Action Screening"],
      recommendedAction: action,
      coverage: "partial",
    },
    scanTimeMs: 1,
    timestamp: 0,
  };
  return opts.actionScreen ? { ...base, actionScreen: opts.actionScreen } : base;
}

function guardWith(
  action: string,
  opts: { primaryThreat?: string; actionScreen?: unknown; guard?: ToolGuardOptions } = {},
) {
  let lastBody: any = {};
  const fetchImpl = (async (_url: string, init?: RequestInit) => {
    lastBody = JSON.parse(String(init?.body ?? "{}"));
    return new Response(JSON.stringify(resp(action, opts)), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;
  const client = new SurfaceClient({ apiKey: "sfk_test", fetch: fetchImpl });
  return { guard: new ToolGuard(client, opts.guard), lastBody: () => lastBody };
}

test("toolCallJson wraps name and args", () => {
  assert.equal(toolCallJson("send_payment", { amount: 10 }), '{"tool":"send_payment","args":{"amount":10}}');
});

for (const action of ["Allow", "Review", "Block"]) {
  test(`screen returns a ${action} decision`, async () => {
    const { guard } = guardWith(action, { primaryThreat: "r" });
    const d = await guard.screen("t", { a: 1 });
    assert.equal(d.action, action);
    assert.equal(d.allowed, action === "Allow");
    assert.equal(d.blocked, action === "Block");
    assert.equal(d.needsReview, action === "Review");
  });
}

test("screen forwards context and the tool call", async () => {
  const context: ActionContext = { principal_domains: ["acme.io"], allowed_egress: ["api.stripe.com"] };
  const { guard, lastBody } = guardWith("Allow", { guard: { context: () => context } });
  await guard.screen("http_request", { url: "https://x" });
  const body = lastBody();
  assert.deepEqual(body.context.principal_domains, ["acme.io"]);
  assert.ok(String(body.payload).includes('"tool":"http_request"'));
  assert.equal(body.label, "http_request.toolcall.json");
});

test("wrap runs the tool on Allow", async () => {
  let ran = false;
  const { guard } = guardWith("Allow");
  const safe = guard.wrap((args: { amount: number }) => {
    ran = true;
    return "done";
  }, "transfer");
  assert.equal(await safe({ amount: 10 }), "done");
  assert.equal(ran, true);
});

test("wrap throws ToolBlocked and does not run on Block", async () => {
  let ran = false;
  const { guard } = guardWith("Block", {
    primaryThreat: "Sends data to a bare-IP address",
    actionScreen: { detected: true, toolCalls: 1, findings: [{ toolName: "transfer", reason: "Sends data to a bare-IP address", evidence: "..." }] },
  });
  const guarded = guard.wrap((_args: unknown) => {
    ran = true;
  }, "transfer");
  await assert.rejects(guarded({ amount: 10 }), (e: unknown) => {
    assert.ok(e instanceof ToolBlocked);
    assert.ok(e.decision.blocked);
    assert.match(e.decision.reason, /bare-IP/);
    assert.equal(e.decision.findings[0].toolName, "transfer");
    return true;
  });
  assert.equal(ran, false);
});

test("Review runs by default but blocks when configured", async () => {
  const run = guardWith("Review").guard.wrap(() => "ok", "t");
  assert.equal(await run(), "ok");

  const strict = guardWith("Review", { guard: { blockOnReview: true } }).guard.wrap(() => "ok", "t");
  await assert.rejects(strict(), (e: unknown) => e instanceof ToolBlocked);
});

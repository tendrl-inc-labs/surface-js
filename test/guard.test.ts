import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SurfaceClient,
  ToolGuard,
  ToolBlocked,
  ToolNeedsReview,
  ValidationError,
  toolCallJson,
  type ActionContext,
  type ToolGuardOptions,
} from "../src/index.js";

function resp(action: string, opts: { primaryThreat?: string; actionScreen?: unknown; actionRisk?: unknown } = {}) {
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
  const withScreen = opts.actionScreen ? { ...base, actionScreen: opts.actionScreen } : base;
  return opts.actionRisk !== undefined ? { ...withScreen, actionRisk: opts.actionRisk } : withScreen;
}

function guardWith(
  action: string,
  opts: { primaryThreat?: string; actionScreen?: unknown; actionRisk?: unknown; guard?: ToolGuardOptions } = {},
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

test("Review is held by default: ToolNeedsReview, a ToolBlocked, tool not run", async () => {
  let ran = false;
  const held = guardWith("Review", { primaryThreat: "needs a look" }).guard.wrap(() => {
    ran = true;
    return "ok";
  }, "t");
  await assert.rejects(held(), (e: unknown) => {
    assert.ok(e instanceof ToolNeedsReview);
    assert.ok(e instanceof ToolBlocked);
    assert.equal(e.name, "ToolNeedsReview");
    assert.ok(e.decision.needsReview);
    return true;
  });
  assert.equal(ran, false);
});

test('onReview "allow" runs a Review', async () => {
  const run = guardWith("Review", { guard: { onReview: "allow" } }).guard.wrap(() => "ok", "t");
  assert.equal(await run(), "ok");
});

test("onReview callback decides a Review (sync and async)", async () => {
  const seen: string[] = [];
  const yes = guardWith("Review", {
    guard: { onReview: (d) => { seen.push(d.action); return true; } },
  }).guard.wrap(() => "ok", "t");
  assert.equal(await yes(), "ok");
  assert.deepEqual(seen, ["Review"]);

  const no = guardWith("Review", { guard: { onReview: () => false } }).guard.wrap(() => "ok", "t");
  await assert.rejects(no(), (e: unknown) => e instanceof ToolNeedsReview);

  const asyncYes = guardWith("Review", { guard: { onReview: async () => true } }).guard.wrap(() => "ok", "t");
  assert.equal(await asyncYes(), "ok");

  const asyncNo = guardWith("Review", { guard: { onReview: async () => false } }).guard.wrap(() => "ok", "t");
  await assert.rejects(asyncNo(), (e: unknown) => e instanceof ToolNeedsReview);
});

test("Block never runs, even with onReview allow or a yes callback", async () => {
  for (const onReview of ["allow", () => true] as const) {
    let ran = false;
    const run = guardWith("Block", { guard: { onReview } }).guard.wrap(() => {
      ran = true;
    }, "t");
    await assert.rejects(run(), (e: unknown) => e instanceof ToolBlocked && !(e instanceof ToolNeedsReview));
    assert.equal(ran, false);
  }
});

test("blockOnReview still works and overrides onReview", async () => {
  const run = guardWith("Review", { guard: { blockOnReview: false } }).guard.wrap(() => "ok", "t");
  assert.equal(await run(), "ok");

  const held = guardWith("Review", { guard: { blockOnReview: true, onReview: "allow" } }).guard.wrap(() => "ok", "t");
  await assert.rejects(held(), (e: unknown) => e instanceof ToolBlocked);

  const allowed = guardWith("Review", { guard: { blockOnReview: false, onReview: "hold" } }).guard.wrap(() => "ok", "t");
  assert.equal(await allowed(), "ok");
});

test("invalid guard options throw", () => {
  assert.throws(
    () => guardWith("Allow", { guard: { strictness: "stirct" as never } }),
    (e: unknown) => e instanceof ValidationError,
  );
  assert.throws(
    () => guardWith("Allow", { guard: { onReview: "block" as never } }),
    (e: unknown) => e instanceof ValidationError,
  );
});

test("guard strictness fills the context unless the context sets it", async () => {
  const a = guardWith("Allow", { guard: { strictness: "strict" } });
  const d = await a.guard.screen("t", {});
  assert.deepEqual(a.lastBody().context, { strictness: "strict" });
  assert.equal(d.strictness, "strict");

  const b = guardWith("Allow", { guard: { strictness: "strict", context: { user_request: "pay the vendor" } } });
  await b.guard.screen("t", {});
  assert.deepEqual(b.lastBody().context, { user_request: "pay the vendor", strictness: "strict" });

  const c = guardWith("Allow", { guard: { strictness: "strict", context: { strictness: "relaxed" } } });
  const dc = await c.guard.screen("t", {});
  assert.equal(c.lastBody().context.strictness, "relaxed");
  assert.equal(dc.strictness, "relaxed");

  const none = guardWith("Allow");
  assert.equal((await none.guard.screen("t", {})).strictness, "balanced");
});

test("screen userRequest fills only a missing request", async () => {
  const a = guardWith("Allow");
  await a.guard.screen("t", {}, { userRequest: "delete my drafts" });
  assert.equal(a.lastBody().context.user_request, "delete my drafts");

  const b = guardWith("Allow", { guard: { context: { user_request: "pay the vendor" } } });
  await b.guard.screen("t", {}, { userRequest: "something else" });
  assert.equal(b.lastBody().context.user_request, "pay the vendor");
});

// --- actionRisk (additive; never changes the verdict) ---

const RISK = {
  probability: 0.87,
  reasons: ["Sends funds to an address not mentioned in the request"],
  action: "Block",
  mode: "shadow",
  calls: 1,
  modelVersion: "action-risk-v1",
  record: { tool: "transfer", verb: "send" },
};

test("actionRisk is parsed onto the result and surfaced on the Decision", async () => {
  const { guard } = guardWith("Allow", { actionRisk: RISK });
  const d = await guard.screen("transfer", { amount: 10 });
  assert.equal(d.result?.actionRisk?.probability, 0.87);
  assert.equal(d.result?.actionRisk?.mode, "shadow");
  assert.equal(d.result?.actionRisk?.modelVersion, "action-risk-v1");
  assert.deepEqual(d.result?.actionRisk?.record, { tool: "transfer", verb: "send" });
  assert.equal(d.riskProbability, 0.87);
  assert.deepEqual(d.riskReasons, RISK.reasons);
  // Shadow Block from the risk engine does not change the scan's Allow.
  assert.equal(d.action, "Allow");
  assert.ok(d.allowed);
});

test("without actionRisk the Decision has no probability and empty reasons", async () => {
  const d = await guardWith("Review").guard.screen("t", {});
  assert.equal(d.result?.actionRisk, undefined);
  assert.equal(d.riskProbability, undefined);
  assert.deepEqual(d.riskReasons, []);
  assert.equal(d.action, "Review");
});

test("actionRisk without reasons yields empty riskReasons", async () => {
  const d = await guardWith("Block", { actionRisk: { probability: 0.2, action: "Allow", mode: "on", calls: 1 } }).guard.screen("t", {});
  assert.equal(d.riskProbability, 0.2);
  assert.deepEqual(d.riskReasons, []);
  assert.equal(d.action, "Block");
});

test("a malformed actionRisk is dropped, not a parse failure", async () => {
  const d = await guardWith("Allow", { actionRisk: "nonsense" }).guard.screen("t", {});
  assert.equal(d.result?.actionRisk, undefined);
  assert.equal(d.riskProbability, undefined);
  assert.equal(d.action, "Allow");
});

test("wrap still runs on Allow when actionRisk is high (shadow)", async () => {
  let ran = false;
  const safe = guardWith("Allow", { actionRisk: { ...RISK, probability: 0.99 } }).guard.wrap(() => {
    ran = true;
    return "ok";
  }, "transfer");
  assert.equal(await safe(), "ok");
  assert.equal(ran, true);
});

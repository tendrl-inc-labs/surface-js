import { test } from "node:test";
import assert from "node:assert/strict";

import { SurfaceClient, type ActionContext } from "../src/index.js";

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
function verdictClient(): { client: SurfaceClient; lastBody: () => any } {
  let body: any = {};
  const fetchImpl = (async (_url: string, init?: RequestInit) => {
    body = JSON.parse(String(init?.body ?? "{}"));
    const payees: Array<{ iban?: string }> = body.context?.known_payees ?? [];
    const known = payees.some((p) => p.iban === "GB29NWBK60161331926819");
    return new Response(JSON.stringify(known ? resp("Clean", "Allow") : resp("Malicious", "Block")), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;
  const client = new SurfaceClient({ apiKey: "sfk_test", fetch: fetchImpl });
  return { client, lastBody: () => body };
}

test("scanPayload forwards context in the request body", async () => {
  const { client, lastBody } = verdictClient();
  const context: ActionContext = {
    principal_domains: ["acme.io"],
    known_payees: [{ name: "Delta", iban: "GB29NWBK60161331926819" }],
    user_request: "pay this month's invoices",
  };
  await client.scanPayload('{"tool":"create_payment","args":{"iban":"GB29NWBK60161331926819"}}', "p.json", { context });
  const ctx = lastBody().context;
  assert.ok(ctx, "context missing from body");
  assert.equal(ctx.user_request, "pay this month's invoices");
  assert.equal(ctx.known_payees[0].iban, "GB29NWBK60161331926819");
});

test("scanPayload omits context when not supplied", async () => {
  const { client, lastBody } = verdictClient();
  await client.scanPayload("hello", "x");
  assert.equal("context" in lastBody(), false);
});

test("context flips a payment verdict Allow<->Block through the SDK", async () => {
  const payload = '{"tool":"create_payment","args":{"iban":"GB29NWBK60161331926819"}}';

  const c1 = verdictClient();
  const withCtx = await c1.client.scanPayload(payload, "p.json", {
    context: { known_payees: [{ name: "Delta", iban: "GB29NWBK60161331926819" }] },
  });
  assert.equal((withCtx as any).safetyScore.recommendedAction, "Allow");

  const c2 = verdictClient();
  const without = await c2.client.scanPayload(payload, "p.json");
  assert.equal((without as any).safetyScore.recommendedAction, "Block");
});

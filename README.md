# Surface JavaScript/TypeScript SDK

TypeScript client for the [Surface](https://tendrl.com/products/surface) file scanning API. Supports two modes: **API mode** (remote scanning via the Surface API) and **Local mode** (scanning via a local scanner daemon). Zero runtime dependencies beyond [Zod](https://zod.dev) for response validation.

## Installation

```bash
npm install github:tendrl-inc-labs/surface-js
```

## Scan Modes

| Mode | Description | API Key Required | Network Required |
|------|-------------|-----------------|-----------------|
| **API** (default) | Sends files to the Surface API | Yes | Yes |
| **Local** | Sends files to a local scanner daemon | No | No |

## Quick Start — API Mode

The shortest integration is `withScan`: hand it a file, your handler receives the `ScanResult`, and files matching `reject` never reach it.

```typescript
import { withScan } from "@tendrl/surface";

// Uses SURFACE_KEY env var automatically
const process = withScan(
  (result) => console.log(result.safetyScore.threatLevel), // Clean, Informational, Suspicious, Risky, or Malicious
  { reject: ["Block"] },                                   // refuse what the scanner recommends blocking
);

await process(file); // you pass the file; the handler gets the result
```

`reject` matches the recommended action (`"Block"`, `"Review"`) or the threat level (`"Malicious"`, `"Suspicious"`) — a rejected file throws `MaliciousFileError` before the handler runs.

Prefer to hold the client yourself? The same scan is one method call:

```typescript
import { SurfaceClient } from "@tendrl/surface";

// Uses SURFACE_KEY env var automatically; pass { apiKey: "sfk_..." } to set it explicitly
const client = new SurfaceClient();

const result = await client.scanFile(file);

// scanFile resolves to ScanResult | DeferredScanResponse, so narrow before use
if ("safetyScore" in result) {
  console.log(result.safetyScore.threatLevel); // Clean, Informational, Suspicious, Risky, or Malicious
}
```

## Quick Start — Local Mode

Requires the scanner daemon running on localhost (e.g. `surface-scanner --daemon --listen=:8090`).

```typescript
import { SurfaceClient } from "@tendrl/surface";

const client = new SurfaceClient({
  mode: "local",
  scannerUrl: "http://127.0.0.1:8090",
});

const result = await client.scanFile(file);
if ("safetyScore" in result) {
  console.log(result.safetyScore.threatLevel);
}
```

The same `scanFile`, `getScan`, and deferred scanning methods work in both modes.

## Authentication

The client checks for an API key in this order:

1. `apiKey` option passed to the constructor
2. `SURFACE_KEY` environment variable (Node.js only)

```bash
export SURFACE_KEY="sfk_your_token_here"
```

In `mode: "api"` an `AuthenticationError` is thrown at construction time if neither is set.

`mode: "local"` is exempt: the local scanner daemon is unauthenticated and the client never sends the key to it, so a local client constructs fine without one. A key is still needed for the hosted calls — `getUsage`, `getAccount`, and `getScanHistory` — which always go to the Surface API regardless of mode.

## Scanning Files

`scanFile` accepts `File`, `Blob`, `Buffer`, or `ReadableStream`:

```typescript
// Scan a file
const fromFile = await client.scanFile(file);

// Node.js — from Buffer
const buf = readFileSync("sample.exe");
const fromBuffer = await client.scanFile(buf, { filename: "sample.exe" });

// Reject malicious files — throws MaliciousFileError
const checked = await client.scanFile(file, { reject: ["Malicious", "Suspicious"] });

// Deferred scan (returns immediately, poll for results)
const deferred = await client.scanFile(largeFile, { defer: true });
if ("scanId" in deferred) {
  const poll = await client.getScan(deferred.scanId);
}
```

## Scan Payload

Scan raw content without writing to disk. Accepts a `string`, `Buffer`, or `Uint8Array` payload and an optional filename label:

```typescript
const result = await client.scanPayload("<?php system('id');", "test.php");
if ("safetyScore" in result) {
  console.log(result.safetyScore.threatLevel);
}
```

String payloads are sent as raw text to `POST /api/scan/payload`. Binary payloads (`Buffer`/`Uint8Array`) are automatically base64-encoded by the SDK. Supports the same options as `scanFile`.

## Action Screening Context

When you scan a tool call an agent is about to make, some actions are dangerous on their own (deleting a database, a secret in a URL) and some are dangerous only relative to *you* — a payment is fine to a known vendor but not to an account you've never paid; an email is fine to a colleague but not leaving to a personal address. The scanner sees the tool call but not your vendor list, your domains, or what the user asked. Pass `context` so it can decide confidently instead of defaulting to a cautious "Review".

```typescript
import type { ActionContext } from "@tendrl/surface";

const context: ActionContext = {
  principal_domains: ["acme.io"],                                       // what counts as "inside"
  allowed_egress: ["api.stripe.com", "hooks.slack.com"],               // outside hosts you legitimately call
  user_request: userMessage,                                           // what the user actually asked
};
const result = await client.scanPayload(toolCallJson, "agent-step.json", { context });
```

**Strictness**

`strictness` sets how readily a judgment call turns into a verdict. Face-dangerous actions (a public share, a secret in a URL, destructive commands) Block at every level.

- **`relaxed`** — stop only what's certainly malicious.
- **`balanced`** (default) — stop what's certainly malicious, ask before risky or irreversible actions.
- **`strict`** — ask or stop on anything that needs judgment, including mail to personal addresses and outside recipients.

```typescript
await client.scanPayload(toolCallJson, "agent-step.json", {
  context: { principal_domains: ["acme.io"], user_request: userMessage, strictness: "strict" },
});

// Or set a default for every scanPayload; a context with its own strictness wins.
const strictClient = new SurfaceClient({ strictness: "strict" });
```

Omit `strictness` and you get `balanced`, so an agent with no configuration isn't stopped while it does routine work. An invalid level throws a `ValidationError`. See the [Python SDK README](https://github.com/tendrl-inc-labs/surface-python#action-screening-context) for the full per-level table.

**Who wrote it: `source`.** Tell Surface where the payload came from and it judges prompt injection accordingly. `"user_prompt"`: the person your agent works for typed it; their own text ("ignore my previous instruction", a story, a pasted log, a translation) is not flagged, and a direct override is held for Review, never blocked, unless `strictness: "strict"`. `"content"`: text the agent reads (a web page, an email, tool output), where a single injection pattern blocks. `"tool_call"`: an action the agent is about to take; `ToolGuard` sets this for you. Omitted, an injection blocks only when two independent signals agree.

```ts
await client.scanPayload(userMessage, "chat.txt", { context: { source: "user_prompt" } });
app.use("/chat", scanMiddleware(client, { source: "user_prompt" }));
```

`createSafeFetch` scans fetched responses as `"content"`.

**Personal mailboxes.** Agents mail customers and candidates on Gmail all day, so below `strict` a send to a personal mailbox is held only on evidence: `user_request` was passed and never named the address (or is itself an override like "ignore previous instructions"), or the message describes bulk data ("all customer records"). Without `user_request` such sends aren't judged below `strict`, so pass it. Sensitive data to a personal mailbox is blocked at `strict`; the recipient's own address never counts as the data. If your users routinely correspond with people on personal mailboxes, set `personal_mail_expected: true` and even a bulk send to an address named in `user_request` passes below `strict`. A live credential still blocks.

**Threat levels.** A Block that rests only on a risky agent action (a tool call, not malware or an injection) is reported as `threatLevel: "Risky"` with `recommendedAction: "Block"`; malware and injections stay `"Malicious"`. Reject on `"Block"` to stop both.

**Content risk.** When the scanner's content-risk engine is on, a scan of content an agent will read (`context: { source: "content" }`, or no source) carries `result.contentRisk`: `probability` (calibrated likelihood that the text tries to steer the agent into a harmful action, such as a planted "note to the assistant" asking it to post data out or change a payout), `action` (what this engine alone recommends), `mode` (`shadow` = reported only) and plain-language `reasons`. It is absent for a user's own prompt and for tool calls.

**Use cases**

- **Data egress** — an email or upload leaving `principal_domains` (or to a free-mail address) is flagged; a recipient the user named in `user_request` is cleared. With `allowed_egress` set, an HTTP POST of data to a host on neither list is flagged for review, so a Stripe or Slack call passes while a POST to an unknown endpoint is caught; a bare-IP destination or a secret in the body is flagged even without it.
- **Dangerous on its face** — a crypto-address payout, a gift-card purchase that returns the codes, `rm -rf` of a data directory, or an admin grant is flagged with no context needed.
- **Task fit** — an action unrelated to `user_request` (a refund during "summarize my tickets") is surfaced.

**Suggested implementation**

- Build `context` from your **trusted application state** — your configured domains, your known integration hosts, the user's message from your own UI. **Never** populate it from the payload being scanned; that would let an attacker vouch for their own request.
- `context` is optional. Pass only the fields you have; those values are validated (a domain list must be an array of strings, `strictness` must be one of the three levels). Omit it and screening still runs on face value — nothing dangerous on its own is missed.
- Only what you put in `context` is sent with the scan (for hosted scans, to the API). Keep `user_request` to the instruction itself.

### Guarding an agent's tool calls

Action screening runs in your agent loop, around tool execution — it is not automatic. `ToolGuard` packages the propose → scan → branch pattern. Either call `screen()` and branch, or `wrap()` a tool so it screens before it runs.

```typescript
import { SurfaceClient, ToolGuard, ToolBlocked, ToolNeedsReview } from "@tendrl/surface";

const guard = new ToolGuard(new SurfaceClient());

// Decide yourself
const d = await guard.screen(call.name, call.args);
if (d.blocked) return refuse(d.reason);          // d.findings has the action + evidence
if (d.needsReview) return escalateToHuman(call, d);
return run(call);

// Or wrap the tool; it throws instead of running on Block, and holds on Review
const safeTransfer = guard.wrap(transferFunds);
try {
  await safeTransfer({ to: "acct_…", amount: 4800 });
} catch (e) {
  if (e instanceof ToolNeedsReview) askUser(e.decision);   // a person should confirm
  else if (e instanceof ToolBlocked) log(e.decision.reason, e.decision.findings);
}
```

Review means a person should confirm the action. A wrapped tool is held on Review by default: it throws `ToolNeedsReview`, which extends `ToolBlocked`, so an existing `catch (e instanceof ToolBlocked)` still stops it. Set `onReview` to change that: `"allow"` runs it, or pass a function that gets the `Decision` and returns (or resolves to) `true` to run it — ask the user there. A Block never runs. `blockOnReview` still works as the older spelling (`true` is `"hold"`, `false` is `"allow"`) and overrides `onReview` when set.

`d.riskProbability` (0–1) and `d.riskReasons` report the action-risk score when the scanner returns `result.actionRisk`; they are `undefined` and `[]` otherwise. They are informational and never change `d.action`.

Context is optional. Pass the fields you have from trusted app state — never from the tool arguments. A function is only needed if the values change per call. `strictness` applies to every call unless the context sets its own, and `d.strictness` reports the level a call was screened at (`"balanced"` when unset). `screen(name, args, { userRequest })` fills `user_request` only when the context has none — handy for passing the run's prompt from a framework hook.

```typescript
const guard = new ToolGuard(new SurfaceClient(), {
  context: {
    principal_domains: ["acme.io"],
    allowed_egress: ["api.stripe.com", "hooks.slack.com"],
    user_request: session.userMessage,
  },
  strictness: "balanced",
  onReview: async (d) => confirmWithUser(d.reason),
});
```

## Agentic Security

Payload scan results may include additional threat detection from agentic security engines. These fields are present on `ScanResult` as optional objects:

- **`codeExtraction`** — embedded code blocks found in the payload (scripts, shell commands)
- **`promptInjection`** — prompt injection attempts detected in text content
- **`sensitiveData`** — exposed credentials, API keys, or PII
- **`toolCallAnalysis`** — suspicious tool/function call patterns
- **`actionRisk`** — for tool-call payloads, a calibrated `probability` (0–1) that the call is harmful, with `reasons`, the engine's own `action`, and `mode` (`"shadow"` does not affect the verdict). Absent when the feature is off or the payload is not a tool call.

```typescript
if ("promptInjection" in result && result.promptInjection?.detected) {
  console.log("Prompt injection detected in payload");
}
```

## Batch Scanning

Scan multiple files concurrently with `scanFiles()`. Use `maxConcurrency` to limit parallel uploads (default 10):

```typescript
const files = [file1, file2, file3]; // File, Blob, or Buffer
const results = await client.scanFiles(files, { maxConcurrency: 5 });

for (const result of results) {
  if ("safetyScore" in result) {
    console.log(result.safetyScore.threatLevel);
  }
}
```

## Middleware

Express/Connect middleware that scans request bodies:

```typescript
import { scanMiddleware } from "@tendrl/surface";

app.use("/api", scanMiddleware(client));
```

For agent-to-agent or outbound HTTP scanning, `createSafeFetch` wraps `fetch` to scan request and/or response bodies:

```typescript
import { createSafeFetch } from "@tendrl/surface";

const safeFetch = createSafeFetch(client);

const res = await safeFetch("https://partner-api.example.com/data", {
  method: "POST",
  body: JSON.stringify(payload),
});
```

Options: `reject`, `label`, `failOpen`, `minSize`, `scanRequest`, `scanResponse`, `onThreat`, `onError`.

`scanResponse` has no counterpart in the Go SDK, whose middleware scans requests
only. `createSafeFetch` wraps a call you are already awaiting, so reading the
response body before handing it back costs nothing structurally; doing the same
inside a Go `http.Handler` would mean buffering the response in a wrapping
`ResponseWriter` and changing the contract every downstream handler relies on.

## Account & Usage

```typescript
const usage = await client.getUsage();
console.log(`${usage.scans_used}/${usage.max_scans} scans used this period (${usage.scans_remaining} remaining)`);

const account = await client.getAccount();
```

## Profiles and API Keys

The SDK doesn't manage scan profiles or API keys. Each key is bound to a profile, and scans use it automatically, so scanning code never needs to choose one. Create and edit profiles and keys in the Surface dashboard, the [REST API](https://tendrl.com/docs/surface/api/), or the [Surface MCP tools](https://tendrl.com/docs/surface/ai/mcp-server/). See [scan profiles](https://tendrl.com/docs/surface/scan-profiles/) for what each setting does.

## Scan History

```typescript
const history = await client.getScanHistory({ page: 1, limit: 25 });
for (const scan of history.scans) {
  console.log(`${scan.filename}: ${scan.threat_level}`);
}
```

## Webhook Verification

```typescript
import { verifyWebhookSignature } from "@tendrl/surface";

const isValid = await verifyWebhookSignature(
  requestBody,
  "your_webhook_secret",
  request.headers["x-surface-signature"],
);
```

Uses Web Crypto API when available, falls back to Node.js `crypto` module.

## Express Integration

```typescript
import express from "express";
import multer from "multer";
import { SurfaceClient, MaliciousFileError } from "@tendrl/surface";

const app = express();
const upload = multer();
const client = new SurfaceClient();

app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const result = await client.scanFile(req.file.buffer, {
      filename: req.file.originalname,
      reject: ["Malicious"],
    });
    if ("safetyScore" in result) {
      res.json({ status: "clean", score: result.safetyScore.score });
    } else {
      res.status(202).json({ status: "queued", scanId: result.scanId });
    }
  } catch (err) {
    if (err instanceof MaliciousFileError) {
      res.status(400).json({ error: "file rejected" });
    } else {
      res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
    }
  }
});

app.listen(3000);
```

## Error Handling

```typescript
import {
  SurfaceError,
  AuthenticationError,
  QuotaExceededError,
  RateLimitError,
  NotFoundError,
  ValidationError,
} from "@tendrl/surface";

try {
  const result = await client.scanFile(file);
} catch (err) {
  if (err instanceof QuotaExceededError) {
    console.log("Monthly scan quota exhausted");
  } else if (err instanceof RateLimitError) {
    console.log("Rate limit hit");
  } else if (err instanceof SurfaceError) {
    console.log(`API error ${err.statusCode}: ${err.message}`);
  }
}
```

## Requirements

- Node.js 18+ or modern browser
- `zod` ^3.22

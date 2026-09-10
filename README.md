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
  (result) => console.log(result.safetyScore.threatLevel), // Clean, Informational, Suspicious, or Malicious
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
  console.log(result.safetyScore.threatLevel); // Clean, Informational, Suspicious, or Malicious
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

`mode: "local"` is exempt: the local scanner daemon is unauthenticated and the client never sends the key to it, so a local client constructs fine without one. A key is still needed for the hosted calls — `getUsage`, `getAccount`, the profile and API-key methods, and `getScanHistory` — which always go to the Surface API regardless of mode.

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

## Agentic Security

Payload scan results may include additional threat detection from agentic security engines. These fields are present on `ScanResult` as optional objects:

- **`codeExtraction`** — embedded code blocks found in the payload (scripts, shell commands)
- **`promptInjection`** — prompt injection attempts detected in text content
- **`sensitiveData`** — exposed credentials, API keys, or PII
- **`toolCallAnalysis`** — suspicious tool/function call patterns

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

app.use("/api", scanMiddleware(client, { reject: ["Malicious"], failOpen: true }));
```

For agent-to-agent or outbound HTTP scanning, `createSafeFetch` wraps `fetch` to scan request and/or response bodies:

```typescript
import { createSafeFetch } from "@tendrl/surface";

const safeFetch = createSafeFetch(client, {
  scanRequest: true,
  scanResponse: true,
  reject: ["Malicious"],
});

const res = await safeFetch("https://partner-api.example.com/data", {
  method: "POST",
  body: JSON.stringify(payload),
});
```

Options: `reject`, `label`, `failOpen`, `minSize`, `scanRequest`, `scanResponse`, `onThreat`, `onError`.

## Account & Usage

```typescript
const usage = await client.getUsage();
console.log(`${usage.scans_used}/${usage.max_scans} scans used this period (${usage.scans_remaining} remaining)`);

const account = await client.getAccount();
```

## Scan Profiles

```typescript
const profiles = await client.listProfiles();

const profile = await client.createProfile({
  name: "Images Only",
  allowed_types: "jpg,jpeg,png,gif,webp",
});

await client.updateProfile(profile.id, { name: "Images & PDFs" });
await client.deleteProfile(profile.id);
```

### Profile Engine Configuration

Control which engines run and configure per-engine settings via `engine_config`:

```typescript
const profile = await client.createProfile({
  name: "Agentic Intake",
  allowed_types: "json,txt,md",
  enable_payload_scan: true,
  engine_config: {
    prompt_injection: { enabled: true },
    sensitive_data: { enabled: true, mask_output: true },
    ml: { threshold: 0.8 },
  },
});
```

Built-in profiles are provisioned server-side; see the [scan profiles documentation](https://tendrl.com/docs/surface/scan-profiles/) for what a new account starts with.

## API Keys

```typescript
const keys = await client.listApiKeys();
const newKey = await client.createApiKey({ label: "Production" });
await client.deleteApiKey(keyId);
```

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

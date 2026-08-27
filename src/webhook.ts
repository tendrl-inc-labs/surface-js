/**
 * Converts a Uint8Array to a hex string.
 */
function toHex(bytes: Uint8Array): string {
  const hexChars: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    hexChars.push(bytes[i].toString(16).padStart(2, "0"));
  }
  return hexChars.join("");
}

/**
 * Computes HMAC-SHA256 using the Web Crypto API (crypto.subtle).
 */
async function hmacSubtle(
  key: Uint8Array,
  data: Uint8Array,
): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, data as BufferSource);
  return toHex(new Uint8Array(signature));
}

/**
 * Computes HMAC-SHA256 using Node.js crypto module as a fallback.
 */
async function hmacNodeFallback(
  key: Uint8Array,
  data: Uint8Array,
): Promise<string> {
  const nodeCrypto = await import("node:crypto");
  const hmac = nodeCrypto.createHmac("sha256", key);
  hmac.update(data);
  return hmac.digest("hex");
}

/**
 * Computes HMAC-SHA256 hex digest, using Web Crypto API when available
 * and falling back to Node.js crypto.
 */
async function computeHmacSha256(
  key: Uint8Array,
  data: Uint8Array,
): Promise<string> {
  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.subtle !== "undefined"
  ) {
    return hmacSubtle(key, data);
  }
  return hmacNodeFallback(key, data);
}

/**
 * Performs a constant-time comparison of two strings to prevent timing attacks.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Verifies a webhook signature against the request body.
 *
 * The signature header is expected to be in the format "sha256=<hex>".
 *
 * @param body - The raw request body as a string or Uint8Array.
 * @param secret - The webhook secret used to sign the payload.
 * @param signatureHeader - The signature header value from the request (e.g. "sha256=abc123...").
 * @returns true if the signature is valid, false otherwise.
 */
export async function verifyWebhookSignature(
  body: string | Uint8Array,
  secret: string,
  signatureHeader: string,
): Promise<boolean> {
  if (!signatureHeader.startsWith("sha256=")) {
    return false;
  }

  const expectedSignature = signatureHeader.slice("sha256=".length);
  const encoder = new TextEncoder();

  const keyBytes = encoder.encode(secret);
  const bodyBytes =
    typeof body === "string" ? encoder.encode(body) : body;

  const computedSignature = await computeHmacSha256(keyBytes, bodyBytes);

  return timingSafeEqual(computedSignature, expectedSignature);
}

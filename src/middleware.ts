import type { SurfaceClient } from "./client.js";
import type { ScanResult } from "./models.js";

/**
 * True if the scan's threat level or recommended action is in `reject`.
 * `reject` must already be lowercased; the two vocabularies don't overlap.
 */
function rejected(
  reject: Set<string>,
  score: ScanResult["safetyScore"],
): boolean {
  return (
    reject.has(score.threatLevel.toLowerCase()) ||
    reject.has(score.recommendedAction.toLowerCase())
  );
}

/**
 * Options for configuring scan middleware behavior.
 */
export interface ScanMiddlewareOptions {
  /** Threat levels ("Malicious"/"Suspicious") or recommended actions ("Block"/"Review") to block, matched case-insensitively. Default: ["Malicious"]. */
  reject?: string[];

  /** Optional label for scans in history. Default: "middleware-scan". */
  label?: string;

  /** If true (default), pass requests through when scanner is unavailable. */
  failOpen?: boolean;

  /** Minimum body size to scan. Skip smaller payloads. Default: 0. */
  minSize?: number;

  /** Callback when a threat is detected, before the 403 is sent. */
  onThreat?: (info: { path: string; result: ScanResult }) => void;

  /** Callback when scanning fails (scanner down, timeout, etc.). */
  onError?: (info: { path: string; error: Error }) => void;
}

/**
 * Express/Connect middleware that scans request bodies for threats.
 *
 * Scans POST/PUT/PATCH request bodies using the payload scan endpoint.
 * Detected threats are blocked with a 403 JSON response.
 *
 * @example
 * ```ts
 * import { SurfaceClient, scanMiddleware } from "@tendrl/surface";
 *
 * const client = new SurfaceClient();
 * app.use("/agent", scanMiddleware(client));
 * ```
 */
export function scanMiddleware(
  client: SurfaceClient,
  options?: ScanMiddlewareOptions,
): (req: any, res: any, next: any) => void {
  const reject = new Set((options?.reject ?? ["Malicious"]).map((l) => l.toLowerCase()));
  const label = options?.label ?? "middleware-scan";
  const failOpen = options?.failOpen ?? true;
  const minSize = options?.minSize ?? 0;

  return async (req: any, res: any, next: any) => {
    // Only scan methods with bodies
    const method = (req.method || "").toUpperCase();
    if (!["POST", "PUT", "PATCH"].includes(method)) {
      return next();
    }

    // Get the body — Express populates req.body with parsed JSON,
    // but we need the raw string for scanning
    let payload: string;
    if (typeof req.body === "string") {
      payload = req.body;
    } else if (req.body && typeof req.body === "object") {
      payload = JSON.stringify(req.body);
    } else if (req.rawBody) {
      payload = req.rawBody.toString("utf-8");
    } else {
      // No body to scan
      return next();
    }

    if (payload.length === 0 || payload.length < minSize) {
      return next();
    }

    try {
      const result = await client.scanPayload(payload, label);

      if ("safetyScore" in result && rejected(reject, result.safetyScore)) {
        if (options?.onThreat) {
          options.onThreat({ path: req.path || req.url, result });
        }
        const scanId = result.requestId || "";
        if (scanId) {
          res.setHeader("X-Surface-Scan-Id", scanId);
        }
        return res.status(403).json({
          error: "request blocked by security scan",
          threatLevel: result.safetyScore.threatLevel,
          threat: result.safetyScore.primaryThreat,
        });
      }

      // Add scan ID to request for downstream visibility
      if ("requestId" in result && result.requestId) {
        req.headers["x-surface-scan-id"] = result.requestId;
      }
    } catch (err: any) {
      if (options?.onError) {
        options.onError({ path: req.path || req.url, error: err });
      }
      if (!failOpen) {
        return res.status(503).json({ error: "security scan unavailable" });
      }
    }

    next();
  };
}

/**
 * Options for the safe fetch wrapper.
 */
export interface SafeFetchOptions extends ScanMiddlewareOptions {
  /** Scan outgoing request bodies. Default: true. */
  scanRequest?: boolean;

  /** Scan incoming response bodies. Default: false. */
  scanResponse?: boolean;
}

/**
 * Creates a fetch wrapper that automatically scans request and/or response bodies.
 *
 * Drop-in replacement for `fetch` — scans payloads transparently.
 * Use this in agents that call other agents to scan everything flowing between them.
 *
 * @example
 * ```ts
 * const safeFetch = createSafeFetch(client);
 *
 * // Use like normal fetch — scanning happens automatically
 * const res = await safeFetch("https://agent-b.example.com/api/chat", {
 *   method: "POST",
 *   body: JSON.stringify({ message: userInput }),
 * });
 * ```
 */
export function createSafeFetch(
  client: SurfaceClient,
  options?: SafeFetchOptions,
): typeof globalThis.fetch {
  const reject = new Set((options?.reject ?? ["Malicious"]).map((l) => l.toLowerCase()));
  const label = options?.label ?? "middleware-scan";
  const failOpen = options?.failOpen ?? true;
  const scanRequest = options?.scanRequest ?? true;
  const scanResponse = options?.scanResponse ?? false;

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

    // Scan outgoing request body
    if (scanRequest && init?.body) {
      const bodyStr =
        typeof init.body === "string"
          ? init.body
          : init.body instanceof ArrayBuffer
            ? new TextDecoder().decode(init.body)
            : init.body.toString();

      if (bodyStr.length > 0) {
        try {
          const result = await client.scanPayload(bodyStr, label);
          if ("safetyScore" in result && rejected(reject, result.safetyScore)) {
            if (options?.onThreat) {
              options.onThreat({ path: url, result });
            }
            throw new Error(
              `Surface: outgoing request blocked — ${result.safetyScore.threatLevel}: ${result.safetyScore.primaryThreat}`,
            );
          }
        } catch (err: any) {
          if (err.message?.startsWith("Surface:")) throw err;
          if (options?.onError) {
            options.onError({ path: url, error: err });
          }
          if (!failOpen) {
            throw new Error("Surface: security scan unavailable");
          }
        }
      }
    }

    // Make the actual request
    const response = await globalThis.fetch(input, init);

    // Scan incoming response body
    if (scanResponse && response.ok) {
      try {
        const responseBody = await response.clone().text();
        if (responseBody.length > 0) {
          const result = await client.scanPayload(responseBody, label);
          if ("safetyScore" in result && rejected(reject, result.safetyScore)) {
            if (options?.onThreat) {
              options.onThreat({ path: url, result });
            }
            throw new Error(
              `Surface: response blocked — ${result.safetyScore.threatLevel}: ${result.safetyScore.primaryThreat}`,
            );
          }
        }
      } catch (err: any) {
        if (err.message?.startsWith("Surface:")) throw err;
        if (options?.onError) {
          options.onError({ path: url, error: err });
        }
        if (!failOpen) {
          throw new Error("Surface: security scan unavailable");
        }
      }
    }

    return response;
  };
}

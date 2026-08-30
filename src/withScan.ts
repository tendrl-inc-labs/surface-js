import { SurfaceClient, type ScanFileOptions, type ScanMode } from "./client.js";
import type { ScanResult } from "./models.js";

/** A file input accepted by {@link withScan}, matching `SurfaceClient.scanFile`. */
export type ScanFileInput = File | Blob | Buffer | ReadableStream;

/** Options for {@link withScan}. */
export interface WithScanOptions {
  /** Reuse an existing client. If omitted, one is created lazily from the fields below. */
  client?: SurfaceClient;
  /** API key for a lazily-created client. Falls back to the SURFACE_KEY env var. */
  apiKey?: string;
  /** Scan mode for a lazily-created client. Default: "api". */
  mode?: ScanMode;
  /** Local scanner daemon URL (mode "local"). Default: "http://127.0.0.1:8090". */
  scannerUrl?: string;
  /** Threat levels to reject. Throws MaliciousFileError before the handler runs. */
  reject?: string | string[];
  /** Filename hint passed through to scanFile (useful for Buffer/stream inputs). */
  filename?: string;
}

/**
 * Wrap a handler so a file is scanned before it runs. The wrapped function
 * takes a file; the handler receives the accepted {@link ScanResult}. If the
 * result matches `reject`, a `MaliciousFileError` is thrown and the handler
 * never runs.
 *
 * This is the JS analogue of the Python SDK's `@scan` decorator — the shortest
 * way to gate code behind a scan without writing the scan/branch yourself.
 *
 * @example
 * ```ts
 * import { withScan } from "@tendrl/surface";
 *
 * const process = withScan(
 *   (result) => store(result),               // only runs for accepted files
 *   { reject: ["Malicious", "Suspicious"] },  // throws MaliciousFileError otherwise
 * );
 *
 * await process(file);
 * ```
 */
export function withScan<A extends unknown[], R>(
  handler: (result: ScanResult, ...args: A) => R,
  options: WithScanOptions = {},
): (file: ScanFileInput, ...args: A) => Promise<Awaited<R>> {
  let client = options.client;
  const getClient = (): SurfaceClient => {
    if (!client) {
      client = new SurfaceClient({
        apiKey: options.apiKey,
        mode: options.mode,
        scannerUrl: options.scannerUrl,
      });
    }
    return client;
  };

  const scanOpts: ScanFileOptions = {};
  if (options.reject !== undefined) scanOpts.reject = options.reject;
  if (options.filename !== undefined) scanOpts.filename = options.filename;

  return async (file: ScanFileInput, ...args: A): Promise<Awaited<R>> => {
    const result = await getClient().scanFile(file, scanOpts);
    // scanFile returns ScanResult | DeferredScanResponse; only the former has a
    // safetyScore. withScan needs the result now, so a deferred scan is a misuse.
    if (!("safetyScore" in result)) {
      throw new TypeError(
        "withScan does not support deferred scans (defer: true).",
      );
    }
    return await handler(result, ...args);
  };
}

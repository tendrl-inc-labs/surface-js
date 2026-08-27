import { z } from "zod";
import {
  SurfaceError,
  AuthenticationError,
  ValidationError,
  NotFoundError,
  QuotaExceededError,
  RateLimitError,
  MaliciousFileError,
} from "./errors.js";
import {
  ScanResultSchema,
  DeferredScanResponseSchema,
  UsageSchema,
  ScanProfileSchema,
  APIKeySchema,
  ScanHistoryPageSchema,
  type ScanResult,
  type DeferredScanResponse,
  type Usage,
  type ScanProfile,
  type APIKey,
  type ScanHistoryPage,
} from "./models.js";

export type ScanMode = "api" | "local";

export interface SurfaceClientOptions {
  /** API key. Falls back to SURFACE_KEY environment variable if not provided. */
  apiKey?: string;
  baseUrl?: string;
  /** Custom fetch implementation. Use this to enable HTTP/2 in Node.js via undici. */
  fetch?: typeof globalThis.fetch;
  /**
   * Scan mode. "api" (default) sends files to the remote Surface API.
   * "local" sends scan requests to a local scanner daemon.
   */
  mode?: ScanMode;
  /** URL of the local scanner daemon. Default: "http://127.0.0.1:8090". Only used in "local" mode. */
  scannerUrl?: string;
}

export interface ScanFileOptions {
  defer?: boolean;
  requestId?: string;
  filename?: string;
  /** Threat levels to reject. Throws MaliciousFileError if the result matches. */
  reject?: string | string[];
}

export class SurfaceClient {
  private baseUrl: string;
  private apiKey: string | undefined;
  private fetch: typeof globalThis.fetch;
  private mode: ScanMode;
  private scannerUrl: string;

  constructor(options: SurfaceClientOptions = {}) {
    this.mode = options.mode ?? "api";
    this.scannerUrl = (options.scannerUrl ?? "http://127.0.0.1:8090").replace(/\/$/, "");
    this.fetch = options.fetch ?? globalThis.fetch;
    // Surface service base; the client appends "/api/..." paths itself.
    this.baseUrl = (options.baseUrl ?? "https://app.tendrl.com/surface").replace(/\/$/, "");

    const resolvedKey: string | undefined =
      options.apiKey ||
      (typeof process !== "undefined" ? process.env?.SURFACE_KEY : undefined);

    // mode "local" talks to an unauthenticated local daemon and never sends the
    // key, so requiring one here made the offline path — the one chosen to keep
    // data off the network — unreachable without a cloud account.
    if (!resolvedKey && this.mode !== "local") {
      throw new AuthenticationError(
        "No API key provided. Pass apiKey or set the SURFACE_KEY environment variable.",
      );
    }
    this.apiKey = resolvedKey;
  }

  /**
   * Throw a typed error from an HTTP response.
   */
  private async throwResponseError(response: Response): Promise<never> {
    const requestId = response.headers.get("x-request-id") ?? undefined;
    let message: string;
    try {
      const body = await response.json();
      message =
        (body as Record<string, unknown>).error as string ??
        (body as Record<string, unknown>).message as string ??
        response.statusText;
    } catch {
      message = response.statusText;
    }

    switch (response.status) {
      case 400:
        throw new ValidationError(message, requestId);
      case 401:
      case 403:
        throw new AuthenticationError(message, requestId);
      case 404:
        throw new NotFoundError(message, requestId);
      case 429: {
        const retryAfter = response.headers.get("retry-after");
        if (retryAfter || message.toLowerCase().includes("rate")) {
          throw new RateLimitError(message, requestId);
        }
        throw new QuotaExceededError(message, requestId);
      }
      default:
        throw new SurfaceError(message, response.status, requestId);
    }
  }

  /**
   * Internal request helper for the Surface API. Sends an HTTP request,
   * maps error status codes to typed error classes, and optionally validates
   * the response body with a Zod schema.
   */
  private async request<T>(
    path: string,
    // ZodType<T> alone forces the schema's input type to equal its output
    // type, which breaks for any schema using .default() — the input has the
    // field optional while the output has it required. Leaving the input
    // parameter open lets those schemas through.
    init?: RequestInit & { schema?: z.ZodType<T, z.ZodTypeDef, unknown> },
  ): Promise<T> {
    const { schema, ...fetchInit } = init ?? {};

    const headers = new Headers(fetchInit.headers);
    headers.set("Authorization", `Bearer ${this.requireKey()}`);

    const url = `${this.baseUrl}${path}`;
    const response = await this.fetch(url, { ...fetchInit, headers });

    if (!response.ok) {
      await this.throwResponseError(response);
    }

    // 204 No Content — nothing to parse
    if (response.status === 204) {
      return undefined as T;
    }

    const json = await response.json();

    if (schema) {
      return schema.parse(json);
    }

    return json as T;
  }

  /** The hosted-API key, or a clear error saying why one is needed. */
  private requireKey(): string {
    if (!this.apiKey) {
      throw new AuthenticationError(
        'This call needs the hosted Surface API. Pass apiKey or set SURFACE_KEY ' +
          '(mode "local" only covers scanning).',
      );
    }
    return this.apiKey;
  }

  /**
   * Internal request helper for the local scanner daemon.
   */
  private async localRequest(path: string, init?: RequestInit): Promise<Response> {
    const url = `${this.scannerUrl}${path}`;
    const response = await this.fetch(url, init);
    if (!response.ok) {
      await this.throwResponseError(response);
    }
    return response;
  }

  /**
   * Upload and scan a file.
   *
   * Returns a ScanResult on synchronous completion (HTTP 200) or a
   * DeferredScanResponse when the scan is queued (HTTP 202).
   */
  async scanFile(
    file: File | Blob | Buffer | ReadableStream,
    options?: ScanFileOptions,
  ): Promise<ScanResult | DeferredScanResponse> {
    const formData = new FormData();

    if (file instanceof ReadableStream) {
      const reader = file.getReader();
      const chunks: Uint8Array[] = [];
      let done = false;
      while (!done) {
        const result = await reader.read();
        done = result.done;
        if (result.value) {
          chunks.push(
            result.value instanceof Uint8Array
              ? result.value
              : new Uint8Array(result.value as ArrayBuffer),
          );
        }
      }
      const blob = new Blob(chunks as BlobPart[]);
      formData.append("file", blob, options?.filename ?? "upload");
    } else if (typeof Buffer !== "undefined" && Buffer.isBuffer(file)) {
      const blob = new Blob([file as BlobPart]);
      formData.append("file", blob, options?.filename ?? "upload");
    } else {
      formData.append("file", file as Blob, options?.filename);
    }

    // Build query params
    const params = new URLSearchParams();
    if (options?.defer) {
      params.set("defer", "true");
    }
    const query = params.toString();

    // The backend derives the request ID from the X-Request-ID header.
    const requestHeaders: Record<string, string> = {};
    if (options?.requestId) {
      requestHeaders["X-Request-ID"] = options.requestId;
    }

    let response: Response;

    if (this.mode === "local") {
      response = await this.localRequest(
        `/scan${query ? `?${query}` : ""}`,
        { method: "POST", body: formData, headers: requestHeaders },
      );
    } else {
      const headers = new Headers(requestHeaders);
      headers.set("Authorization", `Bearer ${this.requireKey()}`);
      const url = `${this.baseUrl}/api/scan${query ? `?${query}` : ""}`;
      response = await this.fetch(url, { method: "POST", headers, body: formData });
      if (!response.ok) {
        await this.throwResponseError(response);
      }
    }

    const json = await response.json();

    if (response.status === 202) {
      return DeferredScanResponseSchema.parse(json);
    }

    const result = ScanResultSchema.parse(json);

    if (options?.reject) {
      // threatLevel is capitalized server-side ("Clean"/"Suspicious"/"Malicious");
      // compare case-insensitively so reject: ["malicious"] matches.
      const levels = (
        typeof options.reject === "string" ? [options.reject] : options.reject
      ).map((l) => l.toLowerCase());
      if (levels.includes(result.safetyScore.threatLevel.toLowerCase())) {
        throw new MaliciousFileError(result);
      }
    }

    return result;
  }

  /**
   * Scan a raw payload without file upload overhead.
   *
   * Useful for middleware scanning — scan API request/response bodies between
   * services. The payload is base64-encoded and sent as JSON.
   *
   * @param payload - Raw content as Buffer, Uint8Array, or string
   * @param label - Optional label for the payload (e.g. "api-request"). Content type is auto-detected.
   * @param options - Scan options (defer, requestId, reject)
   */
  async scanPayload(
    payload: Buffer | Uint8Array | string,
    label: string = "payload.bin",
    options?: ScanFileOptions,
  ): Promise<ScanResult | DeferredScanResponse> {
    // Auto-detect encoding: strings sent raw, binary buffers sent as base64.
    // This avoids unnecessary encoding overhead for text payloads (the common case).
    let reqBody: { payload: string; label: string; encoding?: string };

    if (typeof payload === "string") {
      // String — send raw (no encoding overhead)
      reqBody = { payload, label };
    } else {
      // Buffer/Uint8Array — check if it's valid UTF-8 text
      const buf = typeof Buffer !== "undefined"
        ? Buffer.from(payload)
        : new Uint8Array(payload);
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
        reqBody = { payload: text, label };
      } catch {
        // Binary content — base64 encode
        const b64 = typeof Buffer !== "undefined"
          ? Buffer.from(payload).toString("base64")
          : btoa(String.fromCharCode(...new Uint8Array(payload)));
        reqBody = { payload: b64, label, encoding: "base64" };
      }
    }

    const body = JSON.stringify(reqBody);

    // Build query params
    const params = new URLSearchParams();
    if (options?.defer) {
      params.set("defer", "true");
    }
    const query = params.toString();

    // The backend derives the request ID from the X-Request-ID header.
    const requestHeaders: Record<string, string> = {};
    if (options?.requestId) {
      requestHeaders["X-Request-ID"] = options.requestId;
    }

    let response: Response;

    if (this.mode === "local") {
      response = await this.localRequest(
        `/scan/payload${query ? `?${query}` : ""}`,
        { method: "POST", body, headers: { ...requestHeaders, "Content-Type": "application/json" } },
      );
    } else {
      const headers = new Headers(requestHeaders);
      headers.set("Authorization", `Bearer ${this.requireKey()}`);
      headers.set("Content-Type", "application/json");
      const url = `${this.baseUrl}/api/scan/payload${query ? `?${query}` : ""}`;
      response = await this.fetch(url, { method: "POST", headers, body });
      if (!response.ok) {
        await this.throwResponseError(response);
      }
    }

    const json = await response.json();

    if (response.status === 202) {
      return DeferredScanResponseSchema.parse(json);
    }

    const result = ScanResultSchema.parse(json);

    if (options?.reject) {
      // threatLevel is capitalized server-side ("Clean"/"Suspicious"/"Malicious");
      // compare case-insensitively so reject: ["malicious"] matches.
      const levels = (
        typeof options.reject === "string" ? [options.reject] : options.reject
      ).map((l) => l.toLowerCase());
      if (levels.includes(result.safetyScore.threatLevel.toLowerCase())) {
        throw new MaliciousFileError(result);
      }
    }

    return result;
  }

  /**
   * Scan multiple files concurrently.
   *
   * Returns results in the same order as the input array.
   * Use `maxConcurrency` to limit how many uploads run in parallel (default 10).
   */
  async scanFiles(
    files: (File | Blob | Buffer | ReadableStream)[],
    options?: ScanFileOptions & { maxConcurrency?: number },
  ): Promise<(ScanResult | DeferredScanResponse)[]> {
    const maxConcurrency = options?.maxConcurrency ?? 10;
    const results: (ScanResult | DeferredScanResponse)[] = new Array(
      files.length,
    );
    let nextIndex = 0;

    const worker = async () => {
      while (true) {
        const i = nextIndex++;
        if (i >= files.length) break;
        results[i] = await this.scanFile(files[i], options);
      }
    };

    const workers = Array.from(
      { length: Math.min(maxConcurrency, files.length) },
      () => worker(),
    );
    await Promise.all(workers);
    return results;
  }

  /**
   * Retrieve the result of a deferred scan by its scan ID.
   */
  async getScan(scanId: string): Promise<unknown> {
    if (this.mode === "local") {
      const response = await this.localRequest(`/scan/${encodeURIComponent(scanId)}`);
      return response.json();
    }
    return this.request(`/api/scan/${encodeURIComponent(scanId)}`);
  }

  /**
   * Scan usage for the current billing period (`scans_used`, `max_scans`, `scans_remaining`).
   */
  async getUsage(): Promise<Usage> {
    return this.request("/api/account/usage", {
      schema: UsageSchema,
    });
  }

  /**
   * Get full account details including plan information and scan counts.
   */
  async getAccount(): Promise<unknown> {
    return this.request("/api/account");
  }

  /**
   * List all scan profiles for the current account.
   */
  async listProfiles(): Promise<ScanProfile[]> {
    return this.request("/api/account/profiles", {
      schema: z.array(ScanProfileSchema),
    });
  }

  /**
   * Create a new scan profile.
   */
  async createProfile(params: {
    name: string;
    allowed_types?: string;
    max_file_size?: number;
    block_malicious_ip?: boolean;
    webhook_url?: string;
  }): Promise<ScanProfile> {
    return this.request("/api/account/profiles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
      schema: ScanProfileSchema,
    });
  }

  /**
   * Update an existing scan profile.
   */
  async updateProfile(
    profileId: string,
    params: Record<string, unknown>,
  ): Promise<ScanProfile> {
    return this.request(
      `/api/account/profiles/${encodeURIComponent(profileId)}`,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params),
        schema: ScanProfileSchema,
      },
    );
  }

  /**
   * Delete a scan profile.
   */
  async deleteProfile(profileId: string): Promise<void> {
    return this.request(
      `/api/account/profiles/${encodeURIComponent(profileId)}`,
      { method: "DELETE" },
    );
  }

  /**
   * List all API keys for the current account.
   */
  async listApiKeys(): Promise<APIKey[]> {
    return this.request("/api/account/keys", {
      schema: z.array(APIKeySchema),
    });
  }

  /**
   * Create a new API key.
   */
  async createApiKey(params: {
    label: string;
    profile_id?: string;
  }): Promise<APIKey> {
    return this.request("/api/account/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
      schema: APIKeySchema,
    });
  }

  /**
   * Delete an API key.
   */
  async deleteApiKey(keyId: string): Promise<void> {
    return this.request(
      `/api/account/keys/${encodeURIComponent(keyId)}`,
      { method: "DELETE" },
    );
  }

  /**
   * Get paginated scan history for the current account.
   */
  async getScanHistory(params?: {
    page?: number;
    limit?: number;
  }): Promise<ScanHistoryPage> {
    const query = new URLSearchParams();
    if (params?.page !== undefined) {
      query.set("page", String(params.page));
    }
    if (params?.limit !== undefined) {
      query.set("limit", String(params.limit));
    }
    const qs = query.toString();
    const path = `/api/account/history${qs ? `?${qs}` : ""}`;
    return this.request(path, {
      schema: ScanHistoryPageSchema,
    });
  }
}

import { z } from "zod";
import {
  SurfaceError,
  AuthenticationError,
  ValidationError,
  NotFoundError,
  QuotaExceededError,
  RateLimitError,
  SurfaceUnavailableError,
  MaliciousFileError,
} from "./errors.js";
import {
  ScanResultSchema,
  DeferredScanResponseSchema,
  UsageSchema,
  ScanHistoryPageSchema,
  type ScanResult,
  type DeferredScanResponse,
  type Usage,
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
  /**
   * Default `ActionContext.strictness` for `scanPayload`. A context that sets
   * its own `strictness` wins. Omitted, the scanner uses "balanced".
   */
  strictness?: StrictnessLevel;
  /**
   * Budget for one SDK call in milliseconds, covering every attempt and retry
   * wait. Default 60000. When it runs out the call throws SurfaceUnavailableError.
   */
  timeoutMs?: number;
}

/** Statuses retried inside the call's budget: the scanner is restarting or a proxy lost it. */
const RETRY_STATUSES = new Set([502, 503, 504]);
/** Statuses that mean Surface gave no real answer. */
const UNAVAILABLE_STATUSES = new Set([500, 502, 503, 504]);
/** Transport error codes worth retrying: nothing was processed. DNS failures are not. */
const RETRY_CODES = new Set(["ECONNREFUSED", "ECONNRESET", "EPIPE", "UND_ERR_SOCKET"]);
const MAX_RETRIES = 10;
/** Longest single wait, in seconds, however large Retry-After is. */
const MAX_RETRY_WAIT = 10;
/** Backoff in seconds when the server sends no Retry-After; the last step repeats. */
const BACKOFF = [1, 2, 4, 8];
const TIMED_OUT = Symbol("timed out");

/** A response that came back as a real answer: status and parsed body. */
interface Reply {
  status: number;
  body: unknown;
}

/** Transport error codes on `err`, its cause, and a happy-eyeballs AggregateError's members. */
function errorCodes(err: unknown): string[] {
  const codes: string[] = [];
  const seen = new Set<unknown>();
  const visit = (e: unknown) => {
    if (!e || typeof e !== "object" || seen.has(e)) return;
    seen.add(e);
    const o = e as { code?: unknown; cause?: unknown; errors?: unknown };
    if (typeof o.code === "string") codes.push(o.code);
    visit(o.cause);
    if (Array.isArray(o.errors)) o.errors.forEach(visit);
  };
  visit(err);
  return codes;
}

/** Seconds to wait before the next attempt: Retry-After (capped) or the backoff step. */
function retryWait(retryAfter: string | null, retries: number): number {
  const seconds = retryAfter === null ? NaN : Number(retryAfter.trim());
  if (retryAfter?.trim() && Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds, MAX_RETRY_WAIT);
  }
  return BACKOFF[Math.min(retries, BACKOFF.length - 1)];
}

/** The server's `error` (or `message`) text from a JSON error body. */
function serverMessage(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const b = body as Record<string, unknown>;
  const m = b.error ?? b.message;
  return typeof m === "string" && m ? m : undefined;
}

/** Accepted `ActionContext.strictness` values. */
export const STRICTNESS_LEVELS = ["relaxed", "balanced", "strict"] as const;

/**
 * How readily a judgment call becomes a verdict. relaxed: stop only what is
 * certainly malicious. balanced (the scanner default): also ask before risky
 * or irreversible actions. strict: ask or stop on anything that needs judgment.
 */
export type StrictnessLevel = (typeof STRICTNESS_LEVELS)[number];

/** Throws ValidationError unless `value` is undefined or a strictness level. */
export function checkStrictness(value: unknown): StrictnessLevel | undefined {
  if (value === undefined) return undefined;
  if (!(STRICTNESS_LEVELS as readonly unknown[]).includes(value)) {
    throw new ValidationError(`strictness must be one of ${STRICTNESS_LEVELS.join(", ")}`);
  }
  return value as StrictnessLevel;
}

/** Accepted `ActionContext.source` values: who wrote a scanned payload. */
export const SOURCES = ["user_prompt", "content", "tool_call"] as const;

/**
 * Who wrote a payload. user_prompt: the person the agent works for; a
 * prompt-injection match there is held for Review, never blocked, unless
 * strictness is strict. content: text the agent reads (a web page, an email,
 * tool output); an injection there blocks. tool_call: an action the agent is
 * about to take. Omitted, an injection blocks only on corroborated evidence.
 */
export type PayloadSource = (typeof SOURCES)[number];

/** Throws ValidationError unless `value` is undefined or a source. */
export function checkSource(value: unknown): PayloadSource | undefined {
  if (value === undefined) return undefined;
  if (!(SOURCES as readonly unknown[]).includes(value)) {
    throw new ValidationError(`source must be one of ${SOURCES.join(", ")}`);
  }
  return value as PayloadSource;
}

const hostList = z.array(z.string());

/** Runtime check: fields are optional; values that are passed must be well-formed. */
export const ActionContextSchema = z.object({
  principal_domains: hostList.optional(),
  allowed_egress: hostList.optional(),
  user_request: z.string().optional(),
  strictness: z.enum(STRICTNESS_LEVELS).optional(),
  source: z.enum(SOURCES).optional(),
  personal_mail_expected: z.boolean().optional(),
});

/**
 * Caller-supplied context for action screening of tool-call payloads. Lets the
 * screener tell an action that fits who you are and what the user asked (data
 * going to a declared host, an email the user requested) from one that does not.
 * Build it from trusted application state — never from the content being scanned.
 * Every field is optional; values that are passed are validated.
 * See the "Action Screening Context" section of the README.
 */
export interface ActionContext {
  /** Domains that count as inside the organization, e.g. ["acme.io"]. */
  principal_domains?: string[];
  /**
   * External hosts the agent is expected to send data to (its known
   * integrations), e.g. ["api.stripe.com", "hooks.slack.com"]. With this set,
   * data sent to a host on neither principal_domains nor this list, and not
   * named in user_request, is flagged for review. Left unset, ordinary
   * third-party API calls are not judged (only bare-IP and secret egress are).
   */
  allowed_egress?: string[];
  /** What the user actually asked, from your trusted UI — never lifted from the payload. */
  user_request?: string;
  /**
   * "relaxed" | "balanced" | "strict": how readily a judgment call becomes a
   * verdict. Face-dangerous actions Block at every level. Omitted, the scanner
   * uses "balanced".
   */
  strictness?: StrictnessLevel;
  /** Who wrote the payload; see {@link PayloadSource}. */
  source?: PayloadSource;
  /**
   * Your users routinely correspond with people on personal mailboxes
   * (customers, candidates, family on Gmail). A send to a personal address the
   * user named in user_request is then allowed below "strict".
   */
  personal_mail_expected?: boolean;
}

export interface ScanFileOptions {
  defer?: boolean;
  requestId?: string;
  filename?: string;
  /**
   * Threat levels ("Malicious"/"Suspicious") or recommended actions
   * ("Block"/"Review") to reject. Throws MaliciousFileError if the result matches.
   */
  reject?: string | string[];
  /**
   * Action-screening context for tool-call payloads. Ignored for payloads that
   * are not tool calls. Optional; omit for face-value screening only.
   */
  context?: ActionContext;
}

export class SurfaceClient {
  private baseUrl: string;
  private apiKey: string | undefined;
  private fetch: typeof globalThis.fetch;
  private mode: ScanMode;
  private scannerUrl: string;
  private timeoutMs: number;
  /**
   * @internal Milliseconds per second of retry wait. Tests shrink it so
   * backoff and Retry-After run fast; leave it alone.
   */
  retryUnitMs = 1000;
  /** Default strictness filled into `scanPayload` contexts that leave it unset. */
  readonly strictness: StrictnessLevel | undefined;

  constructor(options: SurfaceClientOptions = {}) {
    this.strictness = checkStrictness(options.strictness);
    this.timeoutMs = options.timeoutMs ?? 60_000;
    if (!(this.timeoutMs > 0)) {
      throw new ValidationError("timeoutMs must be a positive number");
    }
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
   * Turn a non-retried response into a Reply, or throw a typed error. 4xx keep
   * their typed errors; 500/502/503/504, and a body that is not JSON on any
   * other status, mean Surface gave no real answer.
   */
  private toReply(response: Response, text: string): Reply {
    const status = response.status;
    const requestId = response.headers.get("x-request-id") ?? undefined;

    // 204 No Content — nothing to parse
    if (status === 204) {
      return { status, body: undefined };
    }

    let body: unknown;
    let isJson = true;
    try {
      body = JSON.parse(text);
    } catch {
      isJson = false;
    }

    if (response.ok) {
      if (!isJson) {
        throw new SurfaceUnavailableError(
          `Surface unavailable (HTTP ${status}): response was not JSON`,
          status,
          requestId,
        );
      }
      return { status, body };
    }

    const serverText = isJson ? serverMessage(body) : undefined;
    if (UNAVAILABLE_STATUSES.has(status) || (!isJson && (status < 400 || status >= 500))) {
      throw new SurfaceUnavailableError(
        `Surface unavailable (HTTP ${status})${serverText ? `: ${serverText}` : isJson ? "" : ": response was not JSON"}`,
        status,
        requestId,
      );
    }

    const message = serverText ?? response.statusText;
    switch (status) {
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
        throw new SurfaceError(message, status, requestId);
    }
  }

  /**
   * Send one SDK call within its timeout budget. Retries 502/503/504 and
   * refused/reset connections, honoring Retry-After, and never starts a wait
   * that would end past the budget. `init.body` must be reusable across
   * attempts (a string or FormData; streams are buffered before this).
   */
  private async send(url: string, init: RequestInit): Promise<Reply> {
    const deadline = Date.now() + this.timeoutMs;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    // A custom fetch may ignore the signal, so every await also races this.
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(TIMED_OUT);
      }, this.timeoutMs);
    });
    expired.catch(() => {});
    const within = <T>(p: Promise<T>): Promise<T> => Promise.race([p, expired]);

    try {
      for (let retries = 0; ; retries++) {
        let failure: SurfaceUnavailableError;
        let retryAfter: string | null = null;
        try {
          const response = await within(this.fetch(url, { ...init, signal: controller.signal }));
          const text = await within(response.text());
          if (!RETRY_STATUSES.has(response.status)) {
            return this.toReply(response, text);
          }
          retryAfter = response.headers.get("retry-after");
          try {
            this.toReply(response, text);
          } catch (err) {
            failure = err as SurfaceUnavailableError;
          }
        } catch (err) {
          if (err === TIMED_OUT || controller.signal.aborted) {
            throw new SurfaceUnavailableError(
              `Surface unavailable: no answer within ${this.timeoutMs} ms`,
              0,
              undefined,
              err === TIMED_OUT ? undefined : err,
            );
          }
          if (err instanceof SurfaceError) throw err;
          const codes = errorCodes(err);
          const detail = err instanceof Error ? err.message : String(err);
          failure = new SurfaceUnavailableError(
            `Surface unavailable: ${detail}${codes.length ? ` (${codes[0]})` : ""}`,
            0,
            undefined,
            err,
          );
          if (!codes.some((c) => RETRY_CODES.has(c))) throw failure;
        }
        const wait = retryWait(retryAfter, retries) * this.retryUnitMs;
        if (retries >= MAX_RETRIES || Date.now() + wait > deadline) {
          failure!.message += ` (gave up after ${retries + 1} attempts)`;
          throw failure!;
        }
        await new Promise((resolve) => setTimeout(resolve, wait));
      }
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Validate a reply body. A body that is JSON but not the shape the SDK
   * expects is no real answer either.
   */
  private parse<T>(schema: z.ZodType<T, z.ZodTypeDef, unknown>, reply: Reply): T {
    const parsed = schema.safeParse(reply.body);
    if (!parsed.success) {
      throw new SurfaceUnavailableError(
        `Surface unavailable (HTTP ${reply.status}): unexpected response body`,
        reply.status,
        undefined,
        parsed.error,
      );
    }
    return parsed.data;
  }

  /**
   * Internal request helper for the Surface API: adds the key and sends the
   * call within its budget.
   */
  private request(path: string, init: RequestInit = {}): Promise<Reply> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${this.requireKey()}`);
    return this.send(`${this.baseUrl}${path}`, { ...init, headers });
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
   * A scan-endpoint call: the local daemon serves `path` unauthenticated, the
   * API serves it under "/api".
   */
  private scanRequest(path: string, init: RequestInit = {}): Promise<Reply> {
    if (this.mode === "local") {
      return this.send(`${this.scannerUrl}${path}`, init);
    }
    return this.request(`/api${path}`, init);
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

    // FormData re-serializes on every fetch, so a retry resends the whole file.
    const reply = await this.scanRequest(`/scan${query ? `?${query}` : ""}`, {
      method: "POST",
      body: formData,
      headers: requestHeaders,
    });

    if (reply.status === 202) {
      return this.parse(DeferredScanResponseSchema, reply);
    }

    const result = this.parse(ScanResultSchema, reply);

    if (options?.reject) {
      // reject matches on threat level ("Clean"/"Suspicious"/"Malicious") or
      // recommended action ("Allow"/"Review"/"Block") — the two vocabularies
      // don't overlap, so one lowercased set covers both. Case-insensitive.
      const levels = (
        typeof options.reject === "string" ? [options.reject] : options.reject
      ).map((l) => l.toLowerCase());
      const score = result.safetyScore;
      if (
        levels.includes(score.threatLevel.toLowerCase()) ||
        levels.includes(score.recommendedAction.toLowerCase())
      ) {
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
    let reqBody: { payload: string; label: string; encoding?: string; context?: ActionContext };

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

    // The client's strictness fills only a context that leaves it unset.
    let context = options?.context;
    if (this.strictness && context?.strictness === undefined) {
      context = { ...context, strictness: this.strictness };
    }
    if (context) {
      const parsed = ActionContextSchema.safeParse(context);
      if (!parsed.success) {
        throw new ValidationError(parsed.error.issues.map((i) => i.message).join("; "));
      }
      reqBody.context = parsed.data;
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

    const reply = await this.scanRequest(`/scan/payload${query ? `?${query}` : ""}`, {
      method: "POST",
      body,
      headers: { ...requestHeaders, "Content-Type": "application/json" },
    });

    if (reply.status === 202) {
      return this.parse(DeferredScanResponseSchema, reply);
    }

    const result = this.parse(ScanResultSchema, reply);

    if (options?.reject) {
      // reject matches on threat level ("Clean"/"Suspicious"/"Malicious") or
      // recommended action ("Allow"/"Review"/"Block") — the two vocabularies
      // don't overlap, so one lowercased set covers both. Case-insensitive.
      const levels = (
        typeof options.reject === "string" ? [options.reject] : options.reject
      ).map((l) => l.toLowerCase());
      const score = result.safetyScore;
      if (
        levels.includes(score.threatLevel.toLowerCase()) ||
        levels.includes(score.recommendedAction.toLowerCase())
      ) {
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
    return (await this.scanRequest(`/scan/${encodeURIComponent(scanId)}`)).body;
  }

  /**
   * Scan usage for the current billing period (`scans_used`, `max_scans`, `scans_remaining`).
   */
  async getUsage(): Promise<Usage> {
    return this.parse(UsageSchema, await this.request("/api/account/usage"));
  }

  /**
   * Get full account details including plan information and scan counts.
   */
  async getAccount(): Promise<unknown> {
    return (await this.request("/api/account")).body;
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
    return this.parse(ScanHistoryPageSchema, await this.request(path));
  }
}

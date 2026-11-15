export class SurfaceError extends Error {
  public statusCode: number;
  public requestId?: string;
  /** The server's machine-readable `code` field (e.g. `"plan_required"`), if it sent one. */
  public code?: string;

  constructor(message: string, statusCode: number, requestId?: string, code?: string) {
    super(message);
    this.name = "SurfaceError";
    this.statusCode = statusCode;
    this.requestId = requestId;
    if (code !== undefined) this.code = code;
  }
}

export class AuthenticationError extends SurfaceError {
  constructor(message: string, requestId?: string) {
    super(message, 401, requestId);
    this.name = "AuthenticationError";
  }
}

export class ValidationError extends SurfaceError {
  constructor(message: string, requestId?: string) {
    super(message, 400, requestId);
    this.name = "ValidationError";
  }
}

export class NotFoundError extends SurfaceError {
  constructor(message: string, requestId?: string) {
    super(message, 404, requestId);
    this.name = "NotFoundError";
  }
}

/**
 * HTTP 403: the key is valid but may not do this — an RBAC denial
 * (`permission denied: …`), a blocked client IP, or a scan profile with
 * payload scanning turned off. `message` is the server's text and `code` its
 * `code` field, if any. A feature the plan does not include is the subclass
 * {@link PlanRequiredError}. An invalid or missing key is 401 and throws
 * {@link AuthenticationError}.
 */
export class PermissionDeniedError extends SurfaceError {
  constructor(message: string, requestId?: string, code?: string, statusCode = 403) {
    super(message, statusCode, requestId, code);
    this.name = "PermissionDeniedError";
  }
}

/**
 * The account's plan does not include what was asked for: a 403 with
 * `code: "plan_required"`, or the 402 Surface answers when `defer: true` is
 * used on a plan without async scanning (that one carries no `code`). A plan
 * wall, not quota exhaustion. `feature` and `currentPlan` hold the server's
 * `feature` and `current_plan` fields.
 */
export class PlanRequiredError extends PermissionDeniedError {
  public feature?: string;
  public currentPlan?: string;

  constructor(
    message: string,
    requestId?: string,
    code?: string,
    statusCode = 403,
    feature?: string,
    currentPlan?: string,
  ) {
    super(message, requestId, code, statusCode);
    this.name = "PlanRequiredError";
    if (feature !== undefined) this.feature = feature;
    if (currentPlan !== undefined) this.currentPlan = currentPlan;
  }
}

/**
 * HTTP 402: the monthly scan quota is used up
 * (`monthly scan quota exceeded (N/M scans used)`). A 429 is a rate limit and
 * throws {@link RateLimitError} instead.
 */
export class QuotaExceededError extends SurfaceError {
  constructor(message: string, requestId?: string, statusCode = 402) {
    super(message, statusCode, requestId);
    this.name = "QuotaExceededError";
  }
}

/** HTTP 429: too many requests; wait (see `Retry-After`) and retry. */
export class RateLimitError extends SurfaceError {
  constructor(message: string, requestId?: string) {
    super(message, 429, requestId);
    this.name = "RateLimitError";
  }
}

/**
 * Surface gave no real answer: the server could not be reached, the call's
 * timeout ran out, it answered HTTP 500/502/503/504, or the body was not the
 * JSON the SDK expects. `statusCode` is the HTTP status, or 0 when no response
 * arrived. Retries on 502/503/504 and refused/reset connections have already
 * been spent by the time this is thrown.
 */
export class SurfaceUnavailableError extends SurfaceError {
  /** The underlying transport or parse error, when there was one. */
  public cause?: unknown;

  constructor(message: string, statusCode = 0, requestId?: string, cause?: unknown) {
    super(message, statusCode, requestId);
    this.name = "SurfaceUnavailableError";
    if (cause !== undefined) this.cause = cause;
  }
}

export class MaliciousFileError extends Error {
  public result: import("./models.js").ScanResult;

  constructor(result: import("./models.js").ScanResult) {
    super(
      `File rejected: ${result.safetyScore.threatLevel} — ${result.safetyScore.threatSummary}`,
    );
    this.name = "MaliciousFileError";
    this.result = result;
  }
}

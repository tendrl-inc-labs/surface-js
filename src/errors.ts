export class SurfaceError extends Error {
  public statusCode: number;
  public requestId?: string;

  constructor(message: string, statusCode: number, requestId?: string) {
    super(message);
    this.name = "SurfaceError";
    this.statusCode = statusCode;
    this.requestId = requestId;
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

export class QuotaExceededError extends SurfaceError {
  constructor(message: string, requestId?: string) {
    super(message, 429, requestId);
    this.name = "QuotaExceededError";
  }
}

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

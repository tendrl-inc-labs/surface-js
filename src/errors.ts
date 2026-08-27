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

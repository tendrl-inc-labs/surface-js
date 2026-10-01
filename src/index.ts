export { SurfaceClient, STRICTNESS_LEVELS } from "./client.js";
export type {
  SurfaceClientOptions,
  ScanFileOptions,
  ScanMode,
  ActionContext,
  StrictnessLevel,
} from "./client.js";

export { ToolGuard, Decision, ToolBlocked, ToolNeedsReview, toolCallJson } from "./guard.js";
export type {
  ContextSource,
  ToolGuardOptions,
  ToolFinding,
  ReviewPolicy,
  ScreenOptions,
} from "./guard.js";

export {
  SurfaceError,
  AuthenticationError,
  ValidationError,
  NotFoundError,
  QuotaExceededError,
  RateLimitError,
  MaliciousFileError,
} from "./errors.js";

export {
  CVEInfoSchema,
  IOCSchema,
  SafetyScoreSchema,
  ArchiveEntrySchema,
  AnalysisIndicatorSchema,
  OletoolsResultSchema,
  StaticAnalysisResultSchema,
  ActionRiskSchema,
  ScanResultSchema,
  DeferredScanResponseSchema,
  AccountSchema,
  PlanSchema,
  AccountResponseSchema,
  CreditTierSchema,
  DailyVolumeSchema,
  UsageSchema,
  ScanHistoryEntrySchema,
  ScanHistoryPageSchema,
  PlansResponseSchema,
  WebhookPayloadSchema,
} from "./models.js";

export type {
  CVEInfo,
  IOC,
  SafetyScore,
  ArchiveEntry,
  AnalysisIndicator,
  OletoolsResult,
  StaticAnalysisResult,
  ActionRisk,
  ScanResult,
  DeferredScanResponse,
  Account,
  Plan,
  AccountResponse,
  CreditTier,
  DailyVolume,
  Usage,
  ScanHistoryEntry,
  ScanHistoryPage,
  PlansResponse,
  WebhookPayload,
} from "./models.js";

export { verifyWebhookSignature } from "./webhook.js";

export { scanMiddleware, createSafeFetch } from "./middleware.js";
export type { ScanMiddlewareOptions, SafeFetchOptions } from "./middleware.js";

export { withScan } from "./withScan.js";
export type { WithScanOptions, ScanFileInput } from "./withScan.js";

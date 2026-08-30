export { SurfaceClient } from "./client.js";
export type { SurfaceClientOptions, ScanFileOptions, ScanMode } from "./client.js";

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
  ScanResultSchema,
  DeferredScanResponseSchema,
  AccountSchema,
  PlanSchema,
  AccountResponseSchema,
  CreditTierSchema,
  DailyVolumeSchema,
  UsageSchema,
  ScanProfileSchema,
  APIKeySchema,
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
  ScanResult,
  DeferredScanResponse,
  Account,
  Plan,
  AccountResponse,
  CreditTier,
  DailyVolume,
  Usage,
  ScanProfile,
  APIKey,
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

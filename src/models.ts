import { z } from "zod";

// --- Scan-related schemas (camelCase JSON keys) ---

export const CVEInfoSchema = z.object({
  id: z.string(),
  description: z.string(),
  references: z.array(z.string()).optional(),
  cvssScore: z.number().optional(),
  cvssSeverity: z.string().optional(),
  affected: z.string().optional(),
});
export type CVEInfo = z.infer<typeof CVEInfoSchema>;

export const IOCSchema = z.object({
  items: z.array(z.string()).optional(),
  type: z.string().optional(),
});
export type IOC = z.infer<typeof IOCSchema>;

export const SafetyScoreSchema = z.object({
  score: z.number(),
  threatLevel: z.string(),
  confidence: z.string(),
  confidenceScore: z.number(),
  confidenceReason: z.string(),
  primaryThreat: z.string(),
  threatSummary: z.string(),
  enginesUsed: z.array(z.string()),
  info: z.string().optional(),
  recommendedAction: z.string(),
  // How far detection reaches for this file's format: "full" (dedicated ML
  // model plus every engine — PE, ELF), "partial" (every engine runs, detection
  // varies by language — scripts, documents, archives, and the default), or
  // "minimal" (pattern rules and threat feeds only, no ML model exists — Java
  // bytecode, Mach-O, and archives of .class/.dex). A minimal scan never comes
  // back Clean: safety is capped at 85 (Informational), which still recommends
  // Allow. Left optional so an older deployment still parses.
  coverage: z.string().optional(),
  coverageNote: z.string().optional(),
  cveFindings: z.array(CVEInfoSchema).optional(),
});
export type SafetyScore = z.infer<typeof SafetyScoreSchema>;

export const ArchiveEntrySchema = z.object({
  name: z.string(),
  size: z.number().optional(),
  verdict: z.string().optional(),
  threats: z.array(z.string()).optional(),
  iocTypes: z.array(z.string()).optional(),
  iocCount: z.number().optional(),
  skipped: z.boolean().optional(),
  skipReason: z.string().optional(),
});
export type ArchiveEntry = z.infer<typeof ArchiveEntrySchema>;

export const AnalysisIndicatorSchema = z.object({
  type: z.string(),
  keyword: z.string(),
  description: z.string(),
});
export type AnalysisIndicator = z.infer<typeof AnalysisIndicatorSchema>;

export const OletoolsResultSchema = z.object({
  skipped: z.boolean().optional(),
  reason: z.string().optional(),
  suspicious: z.boolean(),
  macros_found: z.boolean(),
  auto_exec: z.boolean().optional(),
  dde_found: z.boolean().optional(),
  indicators: z.array(z.union([AnalysisIndicatorSchema, z.string()])).optional(),
  analysis_results: z.union([z.record(z.unknown()), z.array(z.unknown())]).optional(),
  error: z.string().optional(),
});
export type OletoolsResult = z.infer<typeof OletoolsResultSchema>;

export const StaticAnalysisResultSchema = z.object({
  fileType: z.string(),
  indicators: z.array(z.string()).optional(),
  metadata: z.record(z.unknown()).optional(),
  documentInfo: z.record(z.unknown()).optional(),
});
export type StaticAnalysisResult = z.infer<typeof StaticAnalysisResultSchema>;

export const ScanResultSchema = z.object({
  requestId: z.string().optional(),
  name: z.string(),
  size: z.number(),
  hash: z.string(),
  contentType: z.string(),
  safetyScore: SafetyScoreSchema,
  scanTimeMs: z.number(),
  timestamp: z.number(),
  payloadIOCs: z.array(IOCSchema).optional(),
  archiveEntries: z.array(ArchiveEntrySchema).optional(),
  archiveType: z.string().optional(),
  hasEncryptedEntries: z.boolean().optional(),
  oletoolsResult: OletoolsResultSchema.optional(),
  staticAnalysis: StaticAnalysisResultSchema.optional(),
  scannerVersion: z.string().optional(),
  scannerMode: z.string().optional(),
  scanType: z.string().optional(), // "file" or "payload"

  // Agentic security engines (payload scans)
  codeExtraction: z.any().optional(),
  promptInjection: z.any().optional(),
  sensitiveData: z.any().optional(),
  toolCallAnalysis: z.any().optional(),
  // Action screening: { detected, toolCalls, findings:[{toolName, category,
  // severity, reason, evidence}], contextual }. The reason is also mirrored in
  // safetyScore.primaryThreat.
  actionScreen: z.any().optional(),
});
export type ScanResult = z.infer<typeof ScanResultSchema>;

export const DeferredScanResponseSchema = z.object({
  scanId: z.string(),
  requestId: z.string(),
  status: z.string(),
  message: z.string().optional(),
});
export type DeferredScanResponse = z.infer<typeof DeferredScanResponseSchema>;

// --- Account-related schemas (snake_case JSON keys) ---

export const AccountSchema = z.object({
  id: z.string(),
  email: z.string(),
  display_name: z.string(),
  api_key: z.string(),
  allowed_types: z.string(),
  max_file_size: z.number(),
  block_malicious_ip: z.boolean(),
  plan_id: z.string(),
  monthly_credits: z.number(),
  credits_used: z.number(),
  credits_reset_at: z.string(),
  is_admin: z.boolean(),
  created_at: z.string(),
});
export type Account = z.infer<typeof AccountSchema>;

export const PlanSchema = z.object({
  id: z.string(),
  name: z.string(),
  monthly_credits: z.number(),
  price_cents: z.number(),
  max_file_size_mb: z.number(),
  rate_limit: z.number(),
  description: z.string(),
});
export type Plan = z.infer<typeof PlanSchema>;

export const AccountResponseSchema = z.object({
  account: AccountSchema,
  total_scans: z.number(),
  scans_this_month: z.number(),
  blocked_ips: z.number(),
  plan: PlanSchema,
});
export type AccountResponse = z.infer<typeof AccountResponseSchema>;

export const CreditTierSchema = z.object({
  label: z.string(),
  max_bytes: z.number(),
  credits: z.number(),
});
export type CreditTier = z.infer<typeof CreditTierSchema>;

export const DailyVolumeSchema = z.object({
  dates: z.array(z.string()),
  counts: z.array(z.number()),
});
export type DailyVolume = z.infer<typeof DailyVolumeSchema>;

export const UsageSchema = z.object({
  scans_used: z.number(),
  max_scans: z.number(),
  scans_remaining: z.number(),
  max_file_size_mb: z.number(),
  plan_tier: z.string(),
  reset_at: z.string(),
  daily_volume: DailyVolumeSchema.optional(),
});
export type Usage = z.infer<typeof UsageSchema>;

export const ScanProfileSchema = z.object({
  id: z.string(),
  account_id: z.string(),
  name: z.string(),
  is_default: z.boolean(),
  allowed_types: z.string(),
  max_file_size: z.number(),
  block_malicious_ip: z.boolean(),
  enable_payload_scan: z.boolean().default(true),
  engine_config: z.record(z.any()).optional(),
  webhook_url: z.string(),
  webhook_api_key: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type ScanProfile = z.infer<typeof ScanProfileSchema>;

export const APIKeySchema = z.object({
  id: z.string(),
  account_id: z.string(),
  profile_id: z.string(),
  key_id: z.string(),
  key_value: z.string().optional(),
  label: z.string(),
  last_used_at: z.string().optional(),
  created_at: z.string(),
  profile_name: z.string().optional(),
});
export type APIKey = z.infer<typeof APIKeySchema>;

export const ScanHistoryEntrySchema = z.object({
  id: z.string(),
  account_id: z.string(),
  request_id: z.string(),
  filename: z.string(),
  file_hash: z.string(),
  file_size: z.number(),
  content_type: z.string(),
  safety_score: z.number(),
  threat_level: z.string(),
  primary_threat: z.string(),
  scan_time_ms: z.number(),
  credits_used: z.number(),
  client_ip: z.string(),
  api_key_id: z.string().optional(),
  status: z.string(),
  created_at: z.string(),
});
export type ScanHistoryEntry = z.infer<typeof ScanHistoryEntrySchema>;

export const ScanHistoryPageSchema = z.object({
  scans: z.array(ScanHistoryEntrySchema),
  total: z.number(),
  page: z.number(),
  limit: z.number(),
  has_more: z.boolean(),
});
export type ScanHistoryPage = z.infer<typeof ScanHistoryPageSchema>;

export const PlansResponseSchema = z.object({
  plans: z.array(PlanSchema),
  creditTiers: z.array(CreditTierSchema),
});
export type PlansResponse = z.infer<typeof PlansResponseSchema>;

export const WebhookPayloadSchema = z.object({
  requestId: z.string(),
  file: z.object({
    name: z.string(),
    size: z.number(),
    hash: z.string(),
    contentType: z.string(),
  }),
  scanResult: ScanResultSchema,
  threatLevel: z.string(),
  isMalicious: z.boolean(),
  isSuspicious: z.boolean(),
  timestamp: z.string(),
  scanDuration: z.number(),
});
export type WebhookPayload = z.infer<typeof WebhookPayloadSchema>;

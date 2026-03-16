// ── Legacy types (kept for /predict endpoint compatibility) ──────────────

export interface PredictionRequest {
  raw_request: string;
  network_flow_features?: number[];
}

export interface PredictionResponse {
  raw_request: string;
  anomaly_score: number;
  prediction: "Normal" | "Suspicious";
  threat_type: "Normal" | "Traffic Anomaly" | "Bot Activity" | "Injection Attack";
  features: FeatureVector;
}

export interface FeatureVector {
  request_length: number;
  url_depth: number;
  param_count: number;
  special_char_count: number;
  shannon_entropy: number;
  sql_keyword_score: number;
  script_tag_score: number;
}

// ── Batch Analysis types ─────────────────────────────────────────────────

export interface BatchResultItem {
  raw_request: string;
  anomaly_score: number;
  is_anomaly: boolean;
  threat_type: "Normal" | "SQL Injection" | "XSS Attack" | "Path Traversal" | "Unknown Attack";
}

export interface BatchSummaryResponse {
  total_requests: number;
  normal: number;
  sql_injection: number;
  xss: number;
  path_traversal: number;
  unknown_attack: number;
  contamination_rate: number;  // percentage (0-100)
  results: BatchResultItem[];
}

// ── Unified /analyze endpoint types ─────────────────────────────────────

export interface AnalyzeRequest {
  url?: string;
  raw_request?: string;
  network_flow_features?: number[];
}

export interface ThreatScores {
  url_threat_score: number;
  traffic_anomaly_score: number;
  bot_activity_score: number;
  payload_threat_score: number;
  domain_intel_score: number;
  is_api_request: boolean;
  overall_threat_score: number;
}

export interface ModelDetails {
  model4_classification: string;
  model4_confidence: number;
  traffic_anomaly_detected: boolean;
  bot_activity_detected: boolean;
  payload_attack_detected: boolean;
  payload_threat_type: string | null;
  is_api_request: boolean;
  domain_heuristic_flags: string[];
}

export type Verdict = "Safe" | "Caution" | "Suspicious" | "Dangerous" | "Blocked";

export interface ComprehensiveThreatReport {
  url: string;
  domain: string | null;
  threat_scores: ThreatScores;
  model_details: ModelDetails;
  overall_verdict: Verdict;
  recommendation: string;
  passes_domain_filter: boolean;
  blocked_reason: string | null;
  from_cache: boolean;
  request_type: "Browser" | "API";
}

// ── Shared types ────────────────────────────────────────────────────────

export interface RequestLog {
  id: string;
  timestamp: string;
  raw_request: string;
  anomaly_score: number;
  prediction: "Normal" | "Suspicious";
}

export interface HealthResponse {
  status: string;
  model_loaded: boolean;
  version: string;
}

export interface StatsResponse {
  total_scanned: number;
  normal_count: number;
  suspicious_count: number;
  model_status: string;
}

// ── /bot-analysis endpoint types ─────────────────────────────────────────

export interface BotFlowResult {
  ip: string;
  prediction: 0 | 1;        // 0 = normal, 1 = bot
  probability: number;       // Model 2 confidence (0.0-1.0)
  bot_type: string;          // Type of bot detected
}

export interface BotAnalysisResponse {
  flows_analyzed: number;
  bot_flows: number;
  results: BotFlowResult[];
}

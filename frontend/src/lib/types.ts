export interface PredictionRequest {
  raw_request: string;
}

export interface PredictionResponse {
  raw_request: string;
  anomaly_score: number;
  prediction: "Normal" | "Suspicious";
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

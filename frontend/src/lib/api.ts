import axios from "axios";
import type {
  PredictionRequest,
  PredictionResponse,
  RequestLog,
  HealthResponse,
} from "./types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

export async function predictRequest(
  rawRequest: string
): Promise<PredictionResponse> {
  const payload: PredictionRequest = { raw_request: rawRequest };
  const { data } = await api.post<PredictionResponse>("/predict", payload);
  return data;
}

export async function predictBatch(file: File): Promise<PredictionResponse[]> {
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post<PredictionResponse[]>(
    "/predict/batch",
    formData,
    {
      headers: { "Content-Type": "multipart/form-data" },
    }
  );
  return data;
}

export async function fetchLogs(): Promise<RequestLog[]> {
  const { data } = await api.get<RequestLog[]>("/logs");
  return data;
}

export async function checkHealth(): Promise<HealthResponse> {
  const { data } = await api.get<HealthResponse>("/health");
  return data;
}

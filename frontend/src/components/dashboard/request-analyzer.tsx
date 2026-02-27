"use client";

import { useState } from "react";
import axios from "axios";
import { Send, AlertTriangle, CheckCircle, Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { predictRequest } from "@/lib/api";
import type { PredictionResponse } from "@/lib/types";

export function RequestAnalyzer() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PredictionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await predictRequest(input.trim());
      setResult(response);
    } catch (err) {
      if (axios.isAxiosError(err)) {
        if (!err.response) {
          setError(`Network error — cannot reach backend at ${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}. Is the FastAPI server running?`);
        } else {
          setError(`Backend error ${err.response.status}: ${err.response.data?.detail || err.message}`);
        }
      } else {
        setError(`Unexpected error: ${String(err)}`);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <section id="analyzer">
      <h2 className="text-xl font-semibold mb-6">Analyze Request</h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">HTTP Request Input</CardTitle>
            <CardDescription>
              Paste a raw HTTP request string to analyze for anomalies
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={`GET /api/users?id=1 HTTP/1.1\nHost: example.com\n\nOr try a suspicious one:\nGET /search?q=' OR 1=1 --`}
                className="w-full h-40 px-4 py-3 rounded-lg border border-border bg-background text-foreground text-sm font-mono resize-none focus:outline-none focus:ring-2 focus:ring-ring"
              />
              <button
                type="submit"
                disabled={loading || !input.trim()}
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
                {loading ? "Analyzing..." : "Analyze"}
              </button>
            </form>

            {/* Sample inputs */}
            <div className="mt-6 space-y-2">
              <p className="text-xs text-muted-foreground font-medium">Quick test samples:</p>
              <div className="flex flex-wrap gap-2">
                {[
                  { label: "Normal GET", value: "GET /api/users?page=1&limit=10 HTTP/1.1" },
                  { label: "SQL Injection", value: "GET /login?user=admin' OR 1=1 -- &pass=x" },
                  { label: "XSS Attack", value: "POST /comment?body=<script>alert('xss')</script>" },
                  { label: "Path Traversal", value: "GET /files/../../../etc/passwd HTTP/1.1" },
                ].map((sample) => (
                  <button
                    key={sample.label}
                    onClick={() => setInput(sample.value)}
                    className="text-xs px-3 py-1.5 rounded-full border border-border text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
                  >
                    {sample.label}
                  </button>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Result */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Analysis Result</CardTitle>
            <CardDescription>
              Anomaly score and risk classification
            </CardDescription>
          </CardHeader>
          <CardContent>
            {error && (
              <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
                {error}
              </div>
            )}

            {!result && !error && (
              <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
                <Send className="w-12 h-12 opacity-20 mb-4" />
                <p className="text-sm">Submit a request to see the analysis</p>
              </div>
            )}

            {result && (
              <div className="space-y-6">
                {/* Prediction badge */}
                <div className="flex items-center gap-4">
                  {result.prediction === "Normal" ? (
                    <div className="flex items-center gap-2 px-4 py-2 rounded-full bg-green-500/10 text-green-600 border border-green-500/20">
                      <CheckCircle className="w-5 h-5" />
                      <span className="font-semibold">Normal</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 px-4 py-2 rounded-full bg-red-500/10 text-red-600 border border-red-500/20">
                      <AlertTriangle className="w-5 h-5" />
                      <span className="font-semibold">Suspicious</span>
                    </div>
                  )}
                </div>

                {/* Anomaly score */}
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Anomaly Score</p>
                  <div className="flex items-end gap-2">
                    <span className="text-4xl font-bold">
                      {result.anomaly_score.toFixed(4)}
                    </span>
                    <span className="text-sm text-muted-foreground mb-1">
                      (lower = more suspicious)
                    </span>
                  </div>
                  <div className="w-full h-2 bg-muted rounded-full mt-3 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        result.prediction === "Normal" ? "bg-green-500" : "bg-red-500"
                      }`}
                      style={{
                        width: `${Math.max(5, Math.min(100, (result.anomaly_score + 0.5) * 100))}%`,
                      }}
                    />
                  </div>
                </div>

                {/* Feature breakdown */}
                {result.features && (
                  <div>
                    <p className="text-sm text-muted-foreground mb-3">Feature Vector</p>
                    <div className="grid grid-cols-2 gap-3">
                      {Object.entries(result.features).map(([key, value]) => (
                        <div key={key} className="p-3 rounded-lg bg-muted/50 border border-border">
                          <p className="text-xs text-muted-foreground">{key.replace(/_/g, " ")}</p>
                          <p className="text-sm font-mono font-medium mt-1">
                            {typeof value === "number" ? value.toFixed(3) : value}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

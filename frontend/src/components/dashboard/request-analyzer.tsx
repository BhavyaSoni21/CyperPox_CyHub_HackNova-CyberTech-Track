"use client";

import { useState } from "react";
import axios from "axios";
import {
  Send,
  AlertTriangle,
  CheckCircle,
  Loader2,
  Ban,
  ShieldAlert,
  ShieldCheck,
  Eye,
  Globe,
  Bot,
  Activity,
  Syringe,
  Search,
  Info,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { analyzeRequest } from "@/lib/api";
import type { ComprehensiveThreatReport, Verdict } from "@/lib/types";

const VERDICT_CONFIG: Record<Verdict, {
  label: string;
  color: string;
  bg: string;
  border: string;
  icon: typeof CheckCircle;
}> = {
  Safe: {
    label: "Safe",
    color: "text-green-600",
    bg: "bg-green-500/10",
    border: "border-green-500/20",
    icon: ShieldCheck,
  },
  Caution: {
    label: "Caution",
    color: "text-yellow-600",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/20",
    icon: Eye,
  },
  Suspicious: {
    label: "Suspicious",
    color: "text-orange-600",
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
    icon: AlertTriangle,
  },
  Dangerous: {
    label: "Dangerous",
    color: "text-red-600",
    bg: "bg-red-500/10",
    border: "border-red-500/20",
    icon: ShieldAlert,
  },
  Blocked: {
    label: "Blocked",
    color: "text-gray-600",
    bg: "bg-gray-500/10",
    border: "border-gray-500/20",
    icon: Ban,
  },
};

function ScoreBar({ label, score, icon: Icon }: { label: string; score: number; icon: typeof Activity }) {
  const pct = Math.round(score * 100);
  let barColor = "bg-green-500";
  if (score >= 0.8) barColor = "bg-red-500";
  else if (score >= 0.5) barColor = "bg-orange-500";
  else if (score >= 0.2) barColor = "bg-yellow-500";

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <span className="flex items-center gap-1.5 text-muted-foreground">
          <Icon className="w-3.5 h-3.5" />
          {label}
        </span>
        <span className="font-mono font-medium">{pct}%</span>
      </div>
      <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${barColor}`}
          style={{ width: `${Math.max(2, pct)}%` }}
        />
      </div>
    </div>
  );
}

export function RequestAnalyzer() {
  const [urlInput, setUrlInput] = useState("");
  const [rawInput, setRawInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ComprehensiveThreatReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim() && !rawInput.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await analyzeRequest({
        url: urlInput.trim() || undefined,
        raw_request: rawInput.trim() || undefined,
      });
      setResult(response);
    } catch (err) {
      if (axios.isAxiosError(err)) {
        if (!err.response) {
          setError("Network error — cannot reach backend. Is the FastAPI server running?");
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

  const verdict = result ? VERDICT_CONFIG[result.overall_verdict] || VERDICT_CONFIG.Suspicious : null;
  const VerdictIcon = verdict?.icon || AlertTriangle;

  return (
    <section id="analyzer">
      <div className="flex items-center gap-2 mb-6">
        <h2 className="text-xl font-semibold">Analyze Request</h2>
        <div className="relative group">
          <Info className="w-4 h-4 text-muted-foreground cursor-help" />
          <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 w-72 p-3 rounded-lg bg-popover border border-border shadow-lg text-xs text-muted-foreground opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-150 z-50 pointer-events-none">
            <p className="font-semibold text-foreground mb-1">Request Analysis</p>
            <p className="mb-2">Submit a <span className="text-foreground font-medium">URL</span> and/or a <span className="text-foreground font-medium">raw HTTP request</span> for a 5-model threat analysis.</p>
            <p className="font-medium text-foreground mb-0.5">URL example:</p>
            <code className="block bg-muted px-2 py-1 rounded font-mono mb-2">https://example.com/page?id=1</code>
            <p className="font-medium text-foreground mb-0.5">Raw request example:</p>
            <code className="block bg-muted px-2 py-1 rounded font-mono whitespace-pre">{`GET /login?q='OR 1=1 HTTP/1.1\nHost: example.com`}</code>
            <p className="mt-2">Both fields are optional — fill one or both.</p>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Threat Analysis Input</CardTitle>
            <CardDescription>
              Enter a URL, raw HTTP request, or both for comprehensive analysis
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* URL input */}
              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">URL (optional)</label>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://example.com/path?query=value"
                  className="w-full px-4 py-2.5 rounded-lg border border-border bg-background text-foreground text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>

              {/* Raw request input */}
              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">Raw HTTP Request (optional)</label>
                <textarea
                  value={rawInput}
                  onChange={(e) => setRawInput(e.target.value)}
                  placeholder={`GET /api/users?id=1 HTTP/1.1\nHost: example.com\nUser-Agent: Chrome`}
                  className="w-full h-32 px-4 py-3 rounded-lg border border-border bg-background text-foreground text-sm font-mono resize-none focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>

              <button
                type="submit"
                disabled={loading || (!urlInput.trim() && !rawInput.trim())}
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
              <p className="text-xs text-muted-foreground font-medium">Quick examples:</p>
              <div className="flex flex-wrap gap-2">
                {[
                  {
                    label: "Safe URL",
                    url: "https://github.com/trending",
                    raw: "",
                  },
                  {
                    label: "SQL Injection",
                    url: "",
                    raw: "GET /search?q=' OR 1=1 -- HTTP/1.1\nHost: example.com\nUser-Agent: Python-Requests",
                  },
                  {
                    label: "XSS Attack",
                    url: "",
                    raw: "GET /comment?text=<script>alert('xss')</script> HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0",
                  },
                  {
                    label: "Path Traversal",
                    url: "",
                    raw: "GET /download?file=../../../../etc/passwd HTTP/1.1\nHost: example.com\nUser-Agent: curl/7.68.0",
                  },
                  {
                    label: "Full Analysis",
                    url: "https://example.com/login",
                    raw: "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"user\":\"admin\",\"pass\":\"' OR 1=1\"}",
                  },
                ].map((sample) => (
                  <button
                    key={sample.label}
                    onClick={() => {
                      setUrlInput(sample.url);
                      setRawInput(sample.raw);
                    }}
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
              5-signal fusion with per-model breakdown
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
                <Search className="w-12 h-12 opacity-20 mb-4" />
                <p className="text-sm">Submit a URL or request to see the analysis</p>
              </div>
            )}

            {result && verdict && (
              <div className="space-y-5">
                {/* Verdict Badge */}
                <div className="flex items-center justify-between p-4 rounded-lg border">
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Verdict</p>
                    <p className="text-lg font-semibold">{verdict.label}</p>
                    <p className="text-xs text-muted-foreground mt-1">{result.recommendation}</p>
                  </div>
                  <div className={`flex items-center gap-2 px-4 py-2 rounded-full ${verdict.bg} ${verdict.color} border ${verdict.border}`}>
                    <VerdictIcon className="w-5 h-5" />
                    <span className="font-semibold text-sm">{verdict.label}</span>
                  </div>
                </div>

                {/* Per-Model Score Breakdown */}
                <div>
                  <p className="text-sm text-muted-foreground mb-3">Model Signal Breakdown</p>
                  <div className="space-y-3">
                    {[
                      { label: "URL Reputation",    score: result.threat_scores.url_threat_score,      icon: Globe },
                      { label: "Traffic Anomaly",   score: result.threat_scores.traffic_anomaly_score, icon: Activity },
                      { label: "Bot Activity",      score: result.threat_scores.bot_activity_score,    icon: Bot },
                      { label: "Payload Attack",    score: result.threat_scores.payload_threat_score,  icon: Syringe },
                      { label: "Domain Intelligence", score: result.threat_scores.domain_intel_score,  icon: Search },
                    ]
                      .filter((s) => s.score > 0)
                      .map((s) => (
                        <ScoreBar key={s.label} label={s.label} score={s.score} icon={s.icon} />
                      ))}
                  </div>
                </div>

                {/* Model Details */}
                <div>
                  <p className="text-sm text-muted-foreground mb-3">Detection Details</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-lg bg-muted/50 border border-border">
                      <p className="text-xs text-muted-foreground">URL Classification</p>
                      <p className="text-sm font-medium mt-1 capitalize">
                        {result.model_details.model4_classification}
                      </p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/50 border border-border">
                      <p className="text-xs text-muted-foreground">Traffic Anomaly</p>
                      <p className={`text-sm font-medium mt-1 ${result.model_details.traffic_anomaly_detected ? "text-red-500" : "text-green-500"}`}>
                        {result.model_details.traffic_anomaly_detected ? "Detected" : "Normal"}
                      </p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/50 border border-border">
                      <p className="text-xs text-muted-foreground">Bot Activity</p>
                      <p className={`text-sm font-medium mt-1 ${result.model_details.bot_activity_detected ? "text-red-500" : "text-green-500"}`}>
                        {result.model_details.bot_activity_detected ? "Detected" : "None"}
                      </p>
                    </div>
                    {(result.model_details.payload_attack_detected || result.threat_scores.payload_threat_score > 0) && (
                      <>
                        <div className="p-3 rounded-lg bg-muted/50 border border-border">
                          <p className="text-xs text-muted-foreground">Payload Attack</p>
                          <p className={`text-sm font-medium mt-1 ${result.model_details.payload_attack_detected ? "text-red-500" : "text-green-500"}`}>
                            {result.model_details.payload_attack_detected ? "Detected" : "Clean"}
                          </p>
                        </div>
                        {result.model_details.payload_threat_type && (
                          <div className="p-3 rounded-lg bg-muted/50 border border-border">
                            <p className="text-xs text-muted-foreground">Threat Type</p>
                            <p className="text-sm font-medium mt-1 text-orange-500">
                              {result.model_details.payload_threat_type}
                            </p>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </div>

                {/* Domain heuristic flags */}
                {result.model_details.domain_heuristic_flags.length > 0 && (
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">Heuristic Flags</p>
                    <div className="flex flex-wrap gap-2">
                      {result.model_details.domain_heuristic_flags.map((flag) => (
                        <span
                          key={flag}
                          className="text-xs px-2.5 py-1 rounded-full bg-orange-500/10 text-orange-600 border border-orange-500/20"
                        >
                          {flag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Meta info */}
                <div className="flex items-center gap-4 text-xs text-muted-foreground pt-2 border-t">
                  {result.domain && <span>Domain: {result.domain}</span>}
                  {result.from_cache && <span>Cached result</span>}
                  {result.blocked_reason && <span>Blocked: {result.blocked_reason}</span>}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

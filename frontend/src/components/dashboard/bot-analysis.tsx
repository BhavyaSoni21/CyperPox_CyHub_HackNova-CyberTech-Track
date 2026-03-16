"use client";

import { useRef, useState } from "react";
import { Bug, Upload, FileText, Loader2, ShieldAlert, ShieldCheck, Info } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { runBotAnalysis } from "@/lib/api";
import type { BotAnalysisResponse, BotFlowResult } from "@/lib/types";

export function BotAnalysis() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BotAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);

  const handleFile = async (file: File) => {
    if (!file.name.endsWith(".csv")) {
      setError("Only .csv files are supported.");
      return;
    }
    setFileName(file.name);
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await runBotAnalysis(file);
      setResult(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`Analysis failed: ${msg}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  return (
    <section id="bot-analysis">
      <div className="flex items-center gap-2 mb-6">
        <h2 className="text-xl font-semibold">Bot / Botnet Detection</h2>
        <div className="relative group">
          <Info className="w-4 h-4 text-muted-foreground cursor-help" />
          <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 w-72 p-3 rounded-lg bg-popover border border-border shadow-lg text-xs text-muted-foreground opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-150 z-50 pointer-events-none">
            <p className="font-semibold text-foreground mb-1">Bot / Botnet Detection</p>
            <p className="mb-2">Upload a <span className="text-foreground font-medium">.csv</span> file with three columns: <code className="bg-muted px-1 rounded font-mono">timestamp</code>, <code className="bg-muted px-1 rounded font-mono">ip</code>, and <code className="bg-muted px-1 rounded font-mono">url</code>.</p>
            <p className="font-medium text-foreground mb-0.5">Expected format:</p>
            <code className="block bg-muted px-2 py-1 rounded font-mono whitespace-pre">{`timestamp,ip,url\n12:00:01,192.168.1.5,/login\n12:00:02,192.168.1.5,/login`}</code>
            <p className="mt-2">Model 2 groups rows by IP and classifies each session as <span className="text-foreground font-medium">normal</span>, <span className="text-foreground font-medium">brute-force bot</span>, <span className="text-foreground font-medium">scraper</span>, or <span className="text-foreground font-medium">health-checker</span>.</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload zone */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Bug className="w-5 h-5" /> Bot Analysis Upload
            </CardTitle>
            <CardDescription>
              CSV must have{" "}
              <code className="font-mono text-xs">timestamp</code>,{" "}
              <code className="font-mono text-xs">ip</code>,{" "}
              <code className="font-mono text-xs">url</code> columns
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div
              onDrop={handleDrop}
              onDragOver={(e) => e.preventDefault()}
              onClick={() => inputRef.current?.click()}
              className="border-2 border-dashed border-border rounded-lg p-8 flex flex-col items-center justify-center gap-3 cursor-pointer hover:border-primary/50 hover:bg-accent/30 transition-colors"
            >
              {loading ? (
                <Loader2 className="w-8 h-8 text-primary animate-spin" />
              ) : (
                <FileText className="w-8 h-8 text-muted-foreground" />
              )}
              <p className="text-sm text-muted-foreground text-center">
                {loading ? "Analyzing sessions…" : "Drop a CSV here or click to browse"}
              </p>
              {fileName && !loading && (
                <p className="text-xs text-primary font-mono">{fileName}</p>
              )}
            </div>
            <input
              ref={inputRef}
              type="file"
              accept=".csv"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFile(f);
                e.target.value = "";
              }}
            />
            <div className="p-3 rounded-lg bg-muted/50 text-xs text-muted-foreground space-y-1">
              <p className="font-medium">Expected CSV format:</p>
              <pre className="font-mono whitespace-pre">
                {`timestamp,ip,url\n12:00:01,192.168.1.5,/login\n12:00:02,192.168.1.5,/login`}
              </pre>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </CardContent>
        </Card>

        {/* Results */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Upload className="w-5 h-5" /> Session Results
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!result && !loading && (
              <p className="text-muted-foreground text-sm">
                Upload a log file to see bot detection results.
              </p>
            )}
            {result && (
              <div className="space-y-4">
                {/* Summary cards */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="rounded-lg bg-muted/50 p-3 text-center">
                    <p className="text-2xl font-bold">{result.flows_analyzed}</p>
                    <p className="text-xs text-muted-foreground">Sessions Analyzed</p>
                  </div>
                  <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-center">
                    <p className="text-2xl font-bold text-red-500">{result.bot_flows}</p>
                    <p className="text-xs text-muted-foreground">Bot Sessions</p>
                  </div>
                  <div className="rounded-lg bg-green-500/10 border border-green-500/20 p-3 text-center">
                    <p className="text-2xl font-bold text-green-600">
                      {result.flows_analyzed - result.bot_flows}
                    </p>
                    <p className="text-xs text-muted-foreground">Clean Sessions</p>
                  </div>
                </div>

                {/* Per-IP table */}
                <div className="overflow-y-auto max-h-72 rounded-lg border">
                  <table className="w-full text-sm">
                    <thead className="bg-muted/70 sticky top-0">
                      <tr>
                        <th className="text-left px-4 py-2 font-medium">IP Address</th>
                        <th className="text-left px-4 py-2 font-medium">Verdict</th>
                        <th className="text-left px-4 py-2 font-medium">Type</th>
                        <th className="text-left px-4 py-2 font-medium">Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.results.map((row: BotFlowResult, i: number) => (
                        <tr key={i} className="border-t border-border hover:bg-muted/30">
                          <td className="px-4 py-2 font-mono text-xs">{row.ip}</td>
                          <td className="px-4 py-2">
                            {row.prediction === 1 ? (
                              <span className="flex items-center gap-1 text-red-500">
                                <ShieldAlert className="w-4 h-4" /> Bot
                              </span>
                            ) : (
                              <span className="flex items-center gap-1 text-green-600">
                                <ShieldCheck className="w-4 h-4" /> Normal
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2">
                            <span className={`text-xs px-2 py-0.5 rounded-full ${
                              row.bot_type === "normal"
                                ? "bg-green-500/10 text-green-600"
                                : row.bot_type.includes("brute")
                                ? "bg-red-500/10 text-red-500"
                                : row.bot_type.includes("scraper")
                                ? "bg-orange-500/10 text-orange-500"
                                : row.bot_type.includes("health")
                                ? "bg-blue-500/10 text-blue-500"
                                : "bg-yellow-500/10 text-yellow-600"
                            }`}>
                              {row.bot_type}
                            </span>
                          </td>
                          <td className="px-4 py-2">
                            <div className="flex items-center gap-2">
                              <div className="w-24 h-1.5 rounded-full bg-muted overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${
                                    row.prediction === 1 ? "bg-red-500" : "bg-green-500"
                                  }`}
                                  style={{ width: `${(row.probability * 100).toFixed(0)}%` }}
                                />
                              </div>
                              <span className="text-xs text-muted-foreground">
                                {(row.probability * 100).toFixed(1)}%
                              </span>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

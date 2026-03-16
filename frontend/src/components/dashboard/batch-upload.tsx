"use client";

import { useRef, useState } from "react";
import { Upload, FileText, AlertTriangle, CheckCircle, Loader2, X, Download, FlaskConical, Info } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { predictBatch } from "@/lib/api";
import type { BatchSummaryResponse } from "@/lib/types";

const THREAT_COLORS: Record<string, string> = {
  Normal: "text-green-600",
  "SQL Injection": "text-red-600",
  "XSS Attack": "text-orange-500",
  "Path Traversal": "text-yellow-600",
  "Unknown Attack": "text-purple-500",
};

const THREAT_BG: Record<string, string> = {
  Normal: "bg-green-500/10 border-green-500/20",
  "SQL Injection": "bg-red-500/10 border-red-500/20",
  "XSS Attack": "bg-orange-500/10 border-orange-500/20",
  "Path Traversal": "bg-yellow-500/10 border-yellow-500/20",
  "Unknown Attack": "bg-purple-500/10 border-purple-500/20",
};

export function BatchUpload() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<BatchSummaryResponse | null>(null);
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
    setResults(null);
    try {
      const data = await predictBatch(file);
      setResults(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`Upload failed: ${msg}`);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
    // reset so the same file can be re-selected
    e.target.value = "";
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
  };

  const clearResults = () => {
    setResults(null);
    setFileName(null);
    setError(null);
  };

  const downloadCSV = () => {
    if (!results) return;
    const header = "request,anomaly_score,is_anomaly,threat_type\n";
    const rows = results.results
      .map(
        (r) =>
          `"${r.raw_request.replace(/"/g, '""')}",${r.anomaly_score.toFixed(6)},${r.is_anomaly},${r.threat_type}`
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cyhub_batch_results.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section id="batch-upload">
      <div className="flex items-center gap-2 mb-6">
        <h2 className="text-xl font-semibold">Batch Analysis</h2>
        <div className="relative group">
          <Info className="w-4 h-4 text-muted-foreground cursor-help" />
          <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 w-72 p-3 rounded-lg bg-popover border border-border shadow-lg text-xs text-muted-foreground opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-150 z-50 pointer-events-none">
            <p className="font-semibold text-foreground mb-1">Batch Analysis</p>
            <p className="mb-2">Upload a <span className="text-foreground font-medium">.csv</span> file with a single <code className="bg-muted px-1 rounded font-mono">request</code> column. Each row is one HTTP request to be analyzed.</p>
            <p className="font-medium text-foreground mb-0.5">Expected format:</p>
            <code className="block bg-muted px-2 py-1 rounded font-mono whitespace-pre">{`request\nGET /api/users?id=1 HTTP/1.1\nPOST /login?user=admin'-- HTTP/1.1`}</code>
            <p className="mt-2">Results include threat type and anomaly score per request, plus an overall contamination rate.</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload zone */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Upload className="w-5 h-5" />
              CSV Upload
            </CardTitle>
            <CardDescription>
              Upload a CSV with a <code className="font-mono text-xs bg-muted px-1 py-0.5 rounded">request</code> column
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Drop zone */}
            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onClick={() => inputRef.current?.click()}
              className="border-2 border-dashed border-border rounded-lg p-8 flex flex-col items-center justify-center gap-3 cursor-pointer hover:border-primary/50 hover:bg-accent/30 transition-colors"
            >
              {loading ? (
                <Loader2 className="w-8 h-8 text-primary animate-spin" />
              ) : (
                <FileText className="w-8 h-8 text-muted-foreground" />
              )}
              <p className="text-sm text-muted-foreground text-center">
                {loading
                  ? "Analyzing requests..."
                  : "Drop a CSV here or click to browse"}
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
              onChange={handleInputChange}
            />

            {/* Format hint */}
            <div className="p-3 rounded-lg bg-muted/50 text-xs text-muted-foreground space-y-1">
              <p className="font-medium text-foreground">Expected CSV format:</p>
              <p className="font-mono">request</p>
              <p className="font-mono">GET /api/users?id=1 HTTP/1.1</p>
              <p className="font-mono">POST /login?user=admin&apos;-- HTTP/1.1</p>
            </div>

            {results && (
              <div className="flex gap-2">
                <button
                  onClick={downloadCSV}
                  className="flex-1 inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-border text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
                >
                  <Download className="w-4 h-4" />
                  Export
                </button>
                <button
                  onClick={clearResults}
                  className="inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-border text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
                >
                  <X className="w-4 h-4" />
                  Clear
                </button>
              </div>
            )}

            {error && (
              <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-xs">
                {error}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Results */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-lg">Results</CardTitle>
            <CardDescription>
              {results
                ? `${results.total_requests} requests analyzed`
                : "Upload a CSV file to see batch analysis results"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!results && !loading && (
              <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
                <Upload className="w-10 h-10 opacity-20 mb-3" />
                <p className="text-sm">No results yet</p>
              </div>
            )}

            {loading && (
              <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
                <Loader2 className="w-10 h-10 opacity-40 mb-3 animate-spin" />
                <p className="text-sm">Running Isolation Forest pipeline...</p>
              </div>
            )}

            {results && (
              <div className="space-y-6">
                {/* Summary Header */}
                <div className="p-4 rounded-lg bg-muted/30 border border-border">
                  <h3 className="text-2xl font-bold mb-4">
                    {results.total_requests} Requests Analyzed
                  </h3>

                  {/* Threat Type Counts */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4">
                    {/* Normal */}
                    <div className={`p-3 rounded-lg border ${THREAT_BG["Normal"]}`}>
                      <div className="flex items-center gap-2">
                        <CheckCircle className={`w-4 h-4 ${THREAT_COLORS["Normal"]}`} />
                        <span className={`text-sm font-medium ${THREAT_COLORS["Normal"]}`}>Normal</span>
                      </div>
                      <p className="text-2xl font-bold mt-1">{results.normal}</p>
                    </div>

                    {/* SQL Injection */}
                    {results.sql_injection > 0 && (
                      <div className={`p-3 rounded-lg border ${THREAT_BG["SQL Injection"]}`}>
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`w-4 h-4 ${THREAT_COLORS["SQL Injection"]}`} />
                          <span className={`text-sm font-medium ${THREAT_COLORS["SQL Injection"]}`}>SQL Injection</span>
                        </div>
                        <p className="text-2xl font-bold mt-1">{results.sql_injection}</p>
                      </div>
                    )}

                    {/* XSS Attack */}
                    {results.xss > 0 && (
                      <div className={`p-3 rounded-lg border ${THREAT_BG["XSS Attack"]}`}>
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`w-4 h-4 ${THREAT_COLORS["XSS Attack"]}`} />
                          <span className={`text-sm font-medium ${THREAT_COLORS["XSS Attack"]}`}>XSS Attack</span>
                        </div>
                        <p className="text-2xl font-bold mt-1">{results.xss}</p>
                      </div>
                    )}

                    {/* Path Traversal */}
                    {results.path_traversal > 0 && (
                      <div className={`p-3 rounded-lg border ${THREAT_BG["Path Traversal"]}`}>
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`w-4 h-4 ${THREAT_COLORS["Path Traversal"]}`} />
                          <span className={`text-sm font-medium ${THREAT_COLORS["Path Traversal"]}`}>Path Traversal</span>
                        </div>
                        <p className="text-2xl font-bold mt-1">{results.path_traversal}</p>
                      </div>
                    )}

                    {/* Unknown Attack */}
                    {results.unknown_attack > 0 && (
                      <div className={`p-3 rounded-lg border ${THREAT_BG["Unknown Attack"]}`}>
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`w-4 h-4 ${THREAT_COLORS["Unknown Attack"]}`} />
                          <span className={`text-sm font-medium ${THREAT_COLORS["Unknown Attack"]}`}>Unknown Attack</span>
                        </div>
                        <p className="text-2xl font-bold mt-1">{results.unknown_attack}</p>
                      </div>
                    )}
                  </div>

                  {/* Contamination Rate */}
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-background border border-border">
                    <FlaskConical className="w-5 h-5 text-primary" />
                    <div>
                      <p className="text-sm text-muted-foreground">Contamination Rate</p>
                      <p className={`text-xl font-bold ${results.contamination_rate > 50 ? "text-red-500" : results.contamination_rate > 20 ? "text-yellow-500" : "text-green-500"}`}>
                        {results.contamination_rate.toFixed(1)}%
                      </p>
                    </div>
                    <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-500 ${results.contamination_rate > 50 ? "bg-red-500" : results.contamination_rate > 20 ? "bg-yellow-500" : "bg-green-500"}`}
                        style={{ width: `${Math.min(100, results.contamination_rate)}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Results Table */}
                <div className="overflow-x-auto max-h-80 overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-card">
                      <tr className="border-b border-border text-left text-muted-foreground">
                        <th className="pb-3 pr-4 w-8">#</th>
                        <th className="pb-3 pr-4">Request</th>
                        <th className="pb-3 pr-4 whitespace-nowrap">Threat Type</th>
                        <th className="pb-3 whitespace-nowrap">Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.results.map((r, i) => (
                        <tr
                          key={i}
                          className={`border-b border-border/50 hover:bg-muted/30 transition-colors ${r.is_anomaly ? "bg-red-500/5" : ""}`}
                        >
                          <td className="py-2.5 pr-4 text-muted-foreground text-xs">{i + 1}</td>
                          <td className="py-2.5 pr-4 font-mono text-xs max-w-xs truncate">
                            {r.raw_request}
                          </td>
                          <td className="py-2.5 pr-4">
                            <span
                              className={`inline-flex items-center gap-1 text-xs font-medium ${THREAT_COLORS[r.threat_type] ?? "text-foreground"}`}
                            >
                              {r.threat_type !== "Normal" && (
                                <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                              )}
                              {r.threat_type === "Normal" && (
                                <CheckCircle className="w-3.5 h-3.5 flex-shrink-0" />
                              )}
                              {r.threat_type}
                            </span>
                          </td>
                          <td className="py-2.5 font-mono text-xs text-muted-foreground">
                            {r.anomaly_score.toFixed(4)}
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

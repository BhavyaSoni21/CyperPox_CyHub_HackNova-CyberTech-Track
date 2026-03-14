"use client";

import { useRef, useState } from "react";
import { Upload, FileText, AlertTriangle, CheckCircle, Loader2, X, Download } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { predictBatch } from "@/lib/api";
import type { PredictionResponse } from "@/lib/types";

const THREAT_COLORS: Record<string, string> = {
  Normal: "text-green-600",
  "Traffic Anomaly": "text-orange-500",
  "Bot Activity": "text-yellow-500",
  "Injection Attack": "text-red-600",
};

const THREAT_BG: Record<string, string> = {
  Normal: "bg-green-500/10 border-green-500/20",
  "Traffic Anomaly": "bg-orange-500/10 border-orange-500/20",
  "Bot Activity": "bg-yellow-500/10 border-yellow-500/20",
  "Injection Attack": "bg-red-500/10 border-red-500/20",
};

export function BatchUpload() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<PredictionResponse[] | null>(null);
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
    const header = "request,prediction,threat_type,anomaly_score\n";
    const rows = results
      .map(
        (r) =>
          `"${r.raw_request.replace(/"/g, '""')}",${r.prediction},${r.threat_type},${r.anomaly_score.toFixed(6)}`
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

  // Summary counts
  const summary = results
    ? results.reduce(
        (acc, r) => {
          acc[r.threat_type] = (acc[r.threat_type] ?? 0) + 1;
          return acc;
        },
        {} as Record<string, number>
      )
    : null;

  return (
    <section id="batch-upload">
      <h2 className="text-xl font-semibold mb-6">Batch Analysis</h2>

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
                  ? "Analyzing requests…"
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
                ? `${results.length} requests analyzed`
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
                <p className="text-sm">Running multi-model pipeline…</p>
              </div>
            )}

            {results && summary && (
              <div className="space-y-4">
                {/* Summary badges */}
                <div className="flex flex-wrap gap-2">
                  {Object.entries(summary).map(([type, count]) => (
                    <span
                      key={type}
                      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-medium ${THREAT_BG[type] ?? "bg-muted"} ${THREAT_COLORS[type] ?? "text-foreground"}`}
                    >
                      {type === "Normal" ? (
                        <CheckCircle className="w-3.5 h-3.5" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5" />
                      )}
                      {type}: {count}
                    </span>
                  ))}
                </div>

                {/* Table */}
                <div className="overflow-x-auto max-h-96 overflow-y-auto">
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
                      {results.map((r, i) => (
                        <tr
                          key={i}
                          className="border-b border-border/50 hover:bg-muted/30 transition-colors"
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

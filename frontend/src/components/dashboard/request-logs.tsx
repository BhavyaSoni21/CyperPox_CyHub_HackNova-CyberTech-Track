"use client";

import { useState, useEffect } from "react";
import { History, AlertTriangle, CheckCircle, RefreshCw } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchLogs } from "@/lib/api";
import type { RequestLog } from "@/lib/types";

export function RequestLogs() {
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchLogs();
      setLogs(data);
    } catch {
      setError("Unable to fetch logs. Ensure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section id="logs">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold">Request Logs</h2>
        <button
          onClick={loadLogs}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Loading..." : "Load Logs"}
        </button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <History className="w-5 h-5" />
            Flagged Request History
          </CardTitle>
          <CardDescription>
            Requests scored by the Isolation Forest model, stored in Supabase
          </CardDescription>
        </CardHeader>
        <CardContent>
          {error && (
            <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
              {error}
            </div>
          )}

          {!error && logs.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-muted-foreground">
              <History className="w-10 h-10 opacity-20 mb-3" />
              <p className="text-sm">No logs yet. Click &quot;Load Logs&quot; to fetch from the backend.</p>
            </div>
          )}

          {logs.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="pb-3 pr-4">Timestamp</th>
                    <th className="pb-3 pr-4">Request</th>
                    <th className="pb-3 pr-4">Score</th>
                    <th className="pb-3">Prediction</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr key={log.id} className="border-b border-border/50 hover:bg-muted/30">
                      <td className="py-3 pr-4 text-muted-foreground whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs max-w-xs truncate">
                        {log.raw_request}
                      </td>
                      <td className="py-3 pr-4 font-mono">
                        {log.anomaly_score.toFixed(4)}
                      </td>
                      <td className="py-3">
                        {log.prediction === "Normal" ? (
                          <span className="inline-flex items-center gap-1 text-green-600 text-xs font-medium">
                            <CheckCircle className="w-3.5 h-3.5" />
                            Normal
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-red-600 text-xs font-medium">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            Suspicious
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

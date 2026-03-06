"use client";

import { Shield, Activity, AlertTriangle, CheckCircle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { useEffect, useState } from "react";
import { fetchStats } from "@/lib/api";
import type { StatsResponse } from "@/lib/types";

export function StatsOverview() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadStats = async () => {
      try {
        const data = await fetchStats();
        setStats(data);
      } catch (error) {
        console.error("Failed to fetch stats:", error);
      } finally {
        setLoading(false);
      }
    };

    loadStats();
    // Refresh stats every 30 seconds
    const interval = setInterval(loadStats, 30000);
    return () => clearInterval(interval);
  }, []);

  const statsData = [
    {
      label: "Total Scanned",
      value: loading ? "—" : (stats?.total_scanned ?? 0).toString(),
      icon: Activity,
      description: "Requests analyzed",
      color: "text-primary",
    },
    {
      label: "Normal",
      value: loading ? "—" : (stats?.normal_count ?? 0).toString(),
      icon: CheckCircle,
      description: "Benign requests",
      color: "text-green-500",
    },
    {
      label: "Suspicious",
      value: loading ? "—" : (stats?.suspicious_count ?? 0).toString(),
      icon: AlertTriangle,
      description: "Flagged anomalies",
      color: "text-red-500",
    },
    {
      label: "Model Status",
      value: loading ? "—" : (stats?.model_status ?? "Unknown"),
      icon: Shield,
      description: "Isolation Forest",
      color: "text-primary",
    },
  ];

  return (
    <section>
      <h2 className="text-xl font-semibold mb-6">Overview</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsData.map((stat) => (
          <Card key={stat.label} className="relative overflow-hidden">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{stat.label}</p>
                  <p className="text-3xl font-bold mt-1">{stat.value}</p>
                  <p className="text-xs text-muted-foreground mt-1">{stat.description}</p>
                </div>
                <stat.icon className={`w-10 h-10 ${stat.color} opacity-80`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}

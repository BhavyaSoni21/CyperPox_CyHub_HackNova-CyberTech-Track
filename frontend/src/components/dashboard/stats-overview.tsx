"use client";

import { Shield, Activity, AlertTriangle, CheckCircle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

const stats = [
  {
    label: "Total Scanned",
    value: "—",
    icon: Activity,
    description: "Requests analyzed",
    color: "text-primary",
  },
  {
    label: "Normal",
    value: "—",
    icon: CheckCircle,
    description: "Benign requests",
    color: "text-green-500",
  },
  {
    label: "Suspicious",
    value: "—",
    icon: AlertTriangle,
    description: "Flagged anomalies",
    color: "text-red-500",
  },
  {
    label: "Model Status",
    value: "Ready",
    icon: Shield,
    description: "Isolation Forest",
    color: "text-primary",
  },
];

export function StatsOverview() {
  return (
    <section>
      <h2 className="text-xl font-semibold mb-6">Overview</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => (
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

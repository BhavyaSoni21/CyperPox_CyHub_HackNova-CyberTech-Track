import { RequestAnalyzer } from "@/components/dashboard/request-analyzer";
import { RequestLogs } from "@/components/dashboard/request-logs";
import { StatsOverview } from "@/components/dashboard/stats-overview";
import { HeroSection } from "@/components/dashboard/hero-section";
import { Navigation } from "@/components/navigation";

export default function Home() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Navigation */}
      <Navigation />

      {/* Hero */}
      <HeroSection />

      {/* Main Dashboard */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-12">
        {/* Stats */}
        <StatsOverview />

        {/* Analyzer */}
        <RequestAnalyzer />

        {/* Logs */}
        <RequestLogs />
      </main>

      {/* Footer */}
      <footer className="border-t border-border py-8 text-center text-sm text-muted-foreground">
        <p>CyHub &mdash; AI-Driven Web Anomaly Detection System</p>
        <p className="mt-1">Powered by Isolation Forest &bull; Signature-free &bull; Zero-day capable</p>
      </footer>
    </div>
  );
}

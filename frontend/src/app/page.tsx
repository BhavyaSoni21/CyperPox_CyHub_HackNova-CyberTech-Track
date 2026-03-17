"use client";

import { RequestAnalyzer } from "@/components/dashboard/request-analyzer";
import { RequestLogs } from "@/components/dashboard/request-logs";
import { StatsOverview } from "@/components/dashboard/stats-overview";
import { HeroSection } from "@/components/dashboard/hero-section";
import { BatchUpload } from "@/components/dashboard/batch-upload";
import { BotAnalysis } from "@/components/dashboard/bot-analysis";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";

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

        {/* Batch Upload */}
        <BatchUpload />

        {/* Bot / Botnet Detection */}
        <BotAnalysis />

        {/* Logs */}
        <RequestLogs />
      </main>

      <Footer />
    </div>
  );
}

"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { RequestAnalyzer } from "@/components/dashboard/request-analyzer";
import { RequestLogs } from "@/components/dashboard/request-logs";
import { StatsOverview } from "@/components/dashboard/stats-overview";
import { HeroSection } from "@/components/dashboard/hero-section";
import { BatchUpload } from "@/components/dashboard/batch-upload";
import { BotAnalysis } from "@/components/dashboard/bot-analysis";
import { Navigation } from "@/components/navigation";
import { Footer } from "@/components/footer";
import { useAuth } from "@/contexts/AuthContext";

export default function Home() {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
    }
  }, [user, loading, router]);

  // Show nothing while auth state is resolving or redirect is pending
  if (loading || !user) {
    return null;
  }

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

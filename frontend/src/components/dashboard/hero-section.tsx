"use client";

import { Shield } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Spotlight } from "@/components/ui/spotlight";
import { SplineScene } from "@/components/ui/splite";

export function HeroSection() {
  return (
    <Card className="w-full min-h-[500px] bg-black/[0.96] relative overflow-hidden rounded-none border-x-0 border-t-0">
      <Spotlight
        className="-top-40 left-0 md:left-60 md:-top-20"
        fill="white"
      />

      <div className="flex h-full min-h-[500px]">
        {/* Left content */}
        <div className="flex-1 p-8 md:p-16 relative z-10 flex flex-col justify-center">
          <div className="flex items-center gap-3 mb-6">
            <Shield className="w-10 h-10 text-primary" />
            <span className="text-primary font-semibold text-lg tracking-wide">CyHub</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold bg-clip-text text-transparent bg-gradient-to-b from-neutral-50 to-neutral-400">
            AI-Driven Web
            <br />
            Anomaly Detection
          </h1>
          <p className="mt-6 text-neutral-300 max-w-lg leading-relaxed">
            Detect injection attacks, bot activity, and zero-day threats using unsupervised 
            machine learning. No signatures required — the system learns what normal looks like
            and flags statistical deviations in real-time.
          </p>
          <div className="flex gap-4 mt-8">
            <a
              href="#analyzer"
              className="inline-flex items-center justify-center px-6 py-3 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors"
            >
              Analyze Request
            </a>
            <a
              href="#logs"
              className="inline-flex items-center justify-center px-6 py-3 rounded-lg border border-neutral-700 text-neutral-300 font-medium hover:bg-white/5 transition-colors"
            >
              View Logs
            </a>
          </div>
        </div>

        {/* Right content — 3D scene */}
        <div className="flex-1 relative hidden md:block">
          <SplineScene
            scene="https://prod.spline.design/kZDDjO5HuC9GJUM2/scene.splinecode"
            className="w-full h-full"
          />
        </div>
      </div>
    </Card>
  );
}

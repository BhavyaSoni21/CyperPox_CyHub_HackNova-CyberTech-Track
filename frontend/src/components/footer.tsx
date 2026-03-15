"use client";

import Link from "next/link";
import { Shield, Github, Globe, Zap, Lock, Activity } from "lucide-react";

export function Footer() {
  const year = new Date().getFullYear();

  return (
    <footer className="relative mt-auto border-t border-slate-800/60 bg-slate-950/80 backdrop-blur-xl">
      {/* Top glow line */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 h-px w-2/3 bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Main grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-10 mb-10">
          {/* Brand column */}
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/20 rounded-xl flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <span className="text-white font-bold text-lg tracking-tight">CyHub</span>
                <span className="text-slate-500 text-xs ml-2 font-mono">× CyperPox</span>
              </div>
            </div>
            <p className="text-slate-400 text-sm leading-relaxed">
              AI-driven web anomaly detection — signature-free, zero-day capable, and powered by a 5-signal fusion pipeline.
            </p>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-500/10 border border-green-500/20 text-green-400 text-xs font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                System Operational
              </span>
            </div>
          </div>

          {/* Navigation */}
          <div className="space-y-4">
            <h4 className="text-slate-300 font-semibold text-sm uppercase tracking-widest">Navigation</h4>
            <ul className="space-y-2.5">
              {[
                { label: "Dashboard", href: "/" },
                { label: "About", href: "/about" },
                { label: "Request Analyzer", href: "/#analyzer" },
                { label: "Login", href: "/login" },
              ].map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-slate-400 hover:text-cyan-400 transition-colors text-sm flex items-center gap-2 group"
                  >
                    <span className="w-0 group-hover:w-3 h-px bg-cyan-400 transition-all duration-200" />
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Tech & Links */}
          <div className="space-y-4">
            <h4 className="text-slate-300 font-semibold text-sm uppercase tracking-widest">Powered By</h4>
            <div className="flex flex-wrap gap-2">
              {["FastAPI", "Next.js 16", "HuggingFace", "scikit-learn", "MongoDB", "Firebase", "Vercel"].map((tech) => (
                <span
                  key={tech}
                  className="px-2.5 py-1 rounded-md bg-slate-800/70 border border-slate-700/50 text-slate-400 text-xs font-mono"
                >
                  {tech}
                </span>
              ))}
            </div>
            <div className="flex items-center gap-4 pt-1">
              <a
                href="https://github.com/BhavyaSoni21/CyperPox_CyHub_HackNova-CyberTech-Track"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 hover:text-white transition-colors"
                aria-label="GitHub"
              >
                <Github className="w-5 h-5" />
              </a>
              <a
                href="https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 hover:text-cyan-400 transition-colors"
                aria-label="Live Demo"
              >
                <Globe className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>

        {/* Capabilities strip */}
        <div className="flex flex-wrap justify-center gap-6 py-6 border-y border-slate-800/50 mb-8">
          {[
            { icon: <Zap className="w-3.5 h-3.5" />, label: "Zero-Day Detection" },
            { icon: <Lock className="w-3.5 h-3.5" />, label: "Signature-Free" },
            { icon: <Activity className="w-3.5 h-3.5" />, label: "5-Signal Fusion" },
            { icon: <Shield className="w-3.5 h-3.5" />, label: "Real-Time Analysis" },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-1.5 text-slate-500 text-xs">
              <span className="text-cyan-500/70">{item.icon}</span>
              {item.label}
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500">
          <p>
            &copy; {year}{" "}
            <span className="text-slate-300 font-semibold">CyHub</span>
            <span className="mx-1.5 text-cyan-600">×</span>
            <span className="text-slate-300 font-semibold">CyperPox</span>
            {" "}— All rights reserved.
          </p>
          <div className="flex items-center gap-4">
            <span className="text-slate-600">Built for HackNova CyberTech Track</span>
            <span className="hidden sm:block w-px h-3 bg-slate-700" />
            <span className="font-mono text-slate-600">v2.0 • Signal Fusion</span>
          </div>
        </div>
      </div>
    </footer>
  );
}

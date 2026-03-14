"use client";

import { Shield, Target, Zap, Brain, Lock, TrendingUp, CheckCircle, ArrowRight, Network, Activity, Filter } from 'lucide-react';
import Link from 'next/link';

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800/50 backdrop-blur-xl bg-slate-900/50 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2 group">
              <div className="w-10 h-10 bg-cyan-500/10 rounded-xl flex items-center justify-center group-hover:bg-cyan-500/20 transition">
                <Shield className="w-6 h-6 text-cyan-400" />
              </div>
              <span className="text-xl font-bold text-white">CyHub</span>
            </Link>
            <nav className="flex items-center gap-6">
              <Link href="/" className="text-slate-400 hover:text-white transition">
                Dashboard
              </Link>
              <Link href="/about" className="text-cyan-400 font-medium">
                About
              </Link>
              <Link href="/login" className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition">
                Login
              </Link>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400 text-sm mb-6">
            <Zap className="w-4 h-4" />
            AI-Driven Security
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
            About <span className="text-cyan-400">CyHub</span>
          </h1>
          <p className="text-xl text-slate-300 leading-relaxed">
            A multi-model machine learning pipeline that detects SQL injection, XSS attacks,
            path traversal, bot activity, and zero-day threats — with granular threat classification
            and cloud-powered HuggingFace models.
          </p>
        </div>
      </section>

      {/* Problem Statement */}
      <section className="py-16 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="bg-red-500/5 border border-red-500/20 rounded-2xl p-8 md:p-12">
            <div className="flex items-start gap-4 mb-6">
              <div className="w-12 h-12 bg-red-500/10 rounded-xl flex items-center justify-center shrink-0">
                <Target className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h2 className="text-3xl font-bold text-white mb-4">The Problem</h2>
                <div className="space-y-4 text-slate-300 leading-relaxed">
                  <p>
                    Modern web applications are increasingly vulnerable to <strong className="text-white">injection attacks</strong>,
                    <strong className="text-white"> malicious automated bots</strong>, and <strong className="text-white">zero-day threats</strong>.
                    Traditional security systems rely on static signatures and predefined rules, which fail to detect novel or obfuscated attack patterns.
                  </p>
                  <p>
                    As attackers continuously evolve techniques using encoding, payload obfuscation, and adaptive behavior,
                    signature-based detection becomes insufficient. Organizations need a more intelligent approach that can:
                  </p>
                  <ul className="space-y-2 ml-6">
                    <li className="flex items-start gap-2">
                      <span className="text-red-400 mt-1">•</span>
                      <span>Detect <strong className="text-white">previously unseen attack vectors</strong> without predefined signatures</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-400 mt-1">•</span>
                      <span>Identify <strong className="text-white">obfuscated and encoded payloads</strong> that bypass traditional filters</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-400 mt-1">•</span>
                      <span>Adapt to <strong className="text-white">evolving attack patterns</strong> in real-time</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-400 mt-1">•</span>
                      <span>Reduce false positives while maintaining high detection rates</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Our Solution */}
      <section className="py-16 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-2xl p-8 md:p-12">
            <div className="flex items-start gap-4 mb-8">
              <div className="w-12 h-12 bg-cyan-500/10 rounded-xl flex items-center justify-center shrink-0">
                <Brain className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <h2 className="text-3xl font-bold text-white mb-4">Our Solution</h2>
                <p className="text-slate-300 leading-relaxed text-lg">
                  CyHub implements a <strong className="text-white">three-stage multi-model detection pipeline</strong> that gates
                  on an Isolation Forest base model, then uses cloud-hosted HuggingFace models to classify
                  the specific type of threat with high precision.
                </p>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-6 mb-8">
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
                <div className="flex items-start gap-3 mb-3">
                  <Lock className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2">Signature-Free Detection</h3>
                    <p className="text-slate-400 text-sm">
                      No predefined attack patterns needed. The base Isolation Forest learns what &quot;normal&quot; looks like and flags statistical deviations.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
                <div className="flex items-start gap-3 mb-3">
                  <Network className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2">Multi-Model Pipeline</h3>
                    <p className="text-slate-400 text-sm">
                      Three specialized models run in sequence: Traffic Anomaly (Model 3), Bot Detection (Model 2 via HuggingFace), and Payload Attack (Model 1 via HuggingFace).
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
                <div className="flex items-start gap-3 mb-3">
                  <Activity className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2">Granular Threat Types</h3>
                    <p className="text-slate-400 text-sm">
                      Classifies attacks into: SQL Injection, XSS Attack, Path Traversal, Bot Activity, Traffic Anomaly, or generic Injection Attack — not just &quot;Suspicious&quot;.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
                <div className="flex items-start gap-3 mb-3">
                  <Filter className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2">Reduced False Positives</h3>
                    <p className="text-slate-400 text-sm">
                      UUID/GUID paths are stripped from entropy computation, and hyphens excluded from special-char scoring — preventing legitimate routes from being flagged.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
                <div className="flex items-start gap-3 mb-3">
                  <Zap className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2">Zero-Day Capable</h3>
                    <p className="text-slate-400 text-sm">
                      Detects novel attack vectors never seen before by analyzing behavioral and structural patterns rather than known signatures.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
                <div className="flex items-start gap-3 mb-3">
                  <TrendingUp className="w-5 h-5 text-cyan-400 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-2">Threat Level Scoring</h3>
                    <p className="text-slate-400 text-sm">
                      Every request receives a human-readable threat level — from &quot;Highly Suspicious&quot; to &quot;Very Normal&quot; — based on the anomaly score, not just a binary label.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-16 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-12">How It Works</h2>

          <div className="space-y-6">
            {/* Step 1 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold">
                1
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Feature Engineering</h3>
                <p className="text-slate-300 mb-3">
                  Every HTTP request is converted into a numeric feature vector. UUID/GUID segments are
                  stripped before entropy scoring to prevent false positives on legitimate routes.
                </p>
                <div className="grid md:grid-cols-3 gap-3 text-sm">
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Structural</div>
                    <div className="text-slate-400">Request length, URL depth, parameter count</div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Complexity</div>
                    <div className="text-slate-400">Special characters, Shannon entropy (UUID-stripped)</div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Semantic</div>
                    <div className="text-slate-400">SQL keywords, script injection patterns</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Step 2 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold">
                2
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Base Model Gating (Isolation Forest)</h3>
                <p className="text-slate-300 mb-3">
                  The base Isolation Forest — trained exclusively on normal traffic — acts as the primary gatekeeper.
                  Requests with a positive anomaly score are immediately classified as <strong className="text-white">Normal</strong> and
                  require no further processing. Only negative-score requests proceed to the next stage.
                </p>
              </div>
            </div>

            {/* Step 3 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold">
                3
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Multi-Model Threat Classification</h3>
                <p className="text-slate-300 mb-3">
                  Suspicious requests are classified in priority order across three specialized models:
                </p>
                <div className="grid md:grid-cols-3 gap-3 text-sm">
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Model 3 — Traffic</div>
                    <div className="text-slate-400">RandomForest on 35 network-flow features. Detects Traffic Anomalies.</div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Model 2 — Bot (HF)</div>
                    <div className="text-slate-400">HuggingFace Space. Identifies bot and automated scanner activity.</div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Model 1 — Payload (HF)</div>
                    <div className="text-slate-400">HuggingFace Space. Confirms injection and payload attacks.</div>
                  </div>
                </div>
                <p className="text-slate-400 text-sm mt-3">
                  Feature-based rules (SQL keywords, script patterns, path traversal) run in parallel to provide
                  specific labels: <span className="text-orange-400">SQL Injection</span>, <span className="text-orange-400">XSS Attack</span>, <span className="text-orange-400">Path Traversal</span>.
                </p>
              </div>
            </div>

            {/* Step 4 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold">
                4
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Threat Level Scoring</h3>
                <p className="text-slate-300 mb-3">
                  Each request receives a human-readable threat level alongside its numeric anomaly score:
                </p>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
                  {[
                    { label: "Highly Suspicious",     range: "score < −0.20", color: "text-red-400",    bg: "bg-red-500/10"    },
                    { label: "Moderately Suspicious", range: "−0.20 to −0.08", color: "text-orange-400", bg: "bg-orange-500/10" },
                    { label: "Slightly Suspicious",   range: "−0.08 to 0",    color: "text-yellow-400", bg: "bg-yellow-500/10" },
                    { label: "Slightly Normal",       range: "0 to 0.08",     color: "text-lime-400",   bg: "bg-lime-500/10"   },
                    { label: "Mostly Normal",         range: "0.08 to 0.20",  color: "text-green-400",  bg: "bg-green-500/10"  },
                    { label: "Very Normal",           range: "score > 0.20",  color: "text-green-400",  bg: "bg-green-500/10"  },
                  ].map((level) => (
                    <div key={level.label} className={`${level.bg} rounded-lg p-3 border border-slate-700/30`}>
                      <div className={`${level.color} font-medium mb-1`}>{level.label}</div>
                      <div className="text-slate-400 font-mono text-xs">{level.range}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Tech Stack */}
      <section className="py-16 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-12">Technology Stack</h2>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-3">Backend</h3>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Python 3.10+ & FastAPI
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  scikit-learn (Isolation Forest)
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Pandas & NumPy
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  httpx (async HF calls)
                </li>
              </ul>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-3">ML Models</h3>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Isolation Forest (base)
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Model 1 — HuggingFace Space
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Model 2 — HuggingFace Space
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Model 3 — RandomForest (local)
                </li>
              </ul>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-3">Frontend</h3>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Next.js 16 & React 19
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  TypeScript
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Tailwind CSS
                </li>
              </ul>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-3">Auth & Database</h3>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Firebase Auth
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Google OAuth
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Phone OTP (SMS)
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  MongoDB
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                  Password Strength Enforcement
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-16 px-4">
        <div className="max-w-4xl mx-auto">
          <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-2xl p-8 md:p-12 text-center">
            <h2 className="text-3xl font-bold text-white mb-4">Ready to Secure Your Applications?</h2>
            <p className="text-slate-300 mb-8 text-lg">
              Experience AI-powered anomaly detection and protect your web applications from modern threats.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                href="/login"
                className="inline-flex items-center justify-center gap-2 px-6 py-3 bg-cyan-500 hover:bg-cyan-600 text-white font-medium rounded-lg transition"
              >
                Get Started
                <ArrowRight className="w-5 h-5" />
              </Link>
              <Link
                href="/"
                className="inline-flex items-center justify-center gap-2 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-lg border border-slate-700 transition"
              >
                View Dashboard
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-8 text-center text-sm text-slate-400">
        <div className="max-w-7xl mx-auto px-4">
          <p>CyHub &mdash; AI-Driven Web Anomaly Detection System</p>
          <p className="mt-1">Multi-Model Pipeline &bull; HuggingFace-Powered &bull; Signature-free &bull; Zero-day capable</p>
        </div>
      </footer>
    </div>
  );
}

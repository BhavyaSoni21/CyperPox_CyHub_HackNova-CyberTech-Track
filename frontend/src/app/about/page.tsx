"use client";

import {
  Shield, Target, Zap, Brain, Lock, TrendingUp, CheckCircle,
  ArrowRight, Network, Activity, Filter, Globe, GitMerge, AlertTriangle,
} from 'lucide-react';
import Link from 'next/link';
import { Navigation } from '@/components/navigation';
import { Footer } from '@/components/footer';

const verdicts = [
  { label: "Safe",       range: "score < 0.20",      color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/20" },
  { label: "Caution",    range: "0.20 – 0.50",        color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20" },
  { label: "Suspicious", range: "0.50 – 0.80",        color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  { label: "Dangerous",  range: ">= 0.80",            color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/20" },
  { label: "Blocked",    range: "Hard rule override", color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20" },
];

const signals = [
  { name: "M4 URL Model", api: "0.20", browser: "0.25", desc: "Domain classification — normal / phishing / malware / adult / betting / unknown" },
  { name: "M3 Traffic",   api: "0.20", browser: "0.25", desc: "HuggingFace RandomForest on 35 network-flow features — DDoS, scan patterns" },
  { name: "M2 Bot",       api: "0.20", browser: "0.20", desc: "HuggingFace bot model — automated scanner detection" },
  { name: "M1 Payload",   api: "0.25", browser: "0.15", desc: "HuggingFace payload model — injection, XSS, traversal" },
  { name: "Domain Intel", api: "0.15", browser: "0.15", desc: "URLhaus / PhishTank / Spamhaus + heuristic domain analysis" },
];

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <Navigation />

      {/* Hero */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400 text-sm mb-6">
            <Zap className="w-4 h-4" />
            Signal Fusion v2 · AI-Driven Security
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
            About <span className="text-cyan-400">CyHub</span>
          </h1>
          <p className="text-xl text-slate-300 leading-relaxed max-w-3xl mx-auto">
            A 5-signal fusion pipeline that detects SQL injection, XSS, path traversal, bot activity,
            malicious domains, and zero-day threats — signature-free, zero-day capable, and powered
            by HuggingFace cloud models.
          </p>
        </div>
      </section>

      {/* Problem Statement */}
      <section className="py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="bg-red-500/5 border border-red-500/20 rounded-2xl p-8 md:p-12">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 bg-red-500/10 rounded-xl flex items-center justify-center shrink-0">
                <Target className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h2 className="text-3xl font-bold text-white mb-4">The Problem</h2>
                <div className="space-y-4 text-slate-300 leading-relaxed">
                  <p>
                    Modern web applications face <strong className="text-white">injection attacks</strong>,{" "}
                    <strong className="text-white">malicious bots</strong>, and{" "}
                    <strong className="text-white">zero-day threats</strong> that static WAF signatures
                    consistently miss. Attackers encode payloads, obfuscate structures, and adapt timing
                    to bypass predefined rules.
                  </p>
                  <ul className="space-y-2 ml-4">
                    {[
                      "Detect previously unseen attack vectors without predefined signatures",
                      "Identify obfuscated and encoded payloads that bypass traditional filters",
                      "Classify threats with granular labels — not just a binary Suspicious flag",
                      "Flag malicious domains before a request reaches the application",
                    ].map((item) => (
                      <li key={item} className="flex items-start gap-2">
                        <span className="text-red-400 mt-1 shrink-0">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Our Solution */}
      <section className="py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-2xl p-8 md:p-12">
            <div className="flex items-start gap-4 mb-8">
              <div className="w-12 h-12 bg-cyan-500/10 rounded-xl flex items-center justify-center shrink-0">
                <Brain className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <h2 className="text-3xl font-bold text-white mb-3">Our Solution</h2>
                <p className="text-slate-300 leading-relaxed text-lg">
                  CyHub implements a <strong className="text-white">5-signal fusion engine</strong> —
                  no single model gates the others. Every signal contributes a weighted score, and
                  context-adaptive weights shift automatically between API and Browser request types.
                </p>
              </div>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[
                {
                  icon: <Lock className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "Signature-Free",
                  desc: "The base Isolation Forest is trained only on normal traffic — it learns deviations, not attack patterns.",
                },
                {
                  icon: <GitMerge className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "5-Signal Fusion",
                  desc: "M1 Payload · M2 Bot · M3 Traffic · M4 URL · Domain Intel — all run and fuse into one verdict.",
                },
                {
                  icon: <Activity className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "Granular Threat Labels",
                  desc: "SQL Injection, XSS Attack, Path Traversal, Bot Activity, Traffic Anomaly, Malware Domain — not just &quot;Suspicious&quot;.",
                },
                {
                  icon: <Filter className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "Low False Positives",
                  desc: "UUID/GUID path segments stripped from entropy, hyphens excluded from special-char scoring. Legitimate REST routes stay clean.",
                },
                {
                  icon: <Zap className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "Zero-Day Capable",
                  desc: "Statistical outlier detection catches novel attack vectors with no prior signature needed.",
                },
                {
                  icon: <Globe className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "Domain Intelligence",
                  desc: "Live blocklists from URLhaus, PhishTank, and Spamhaus combined with M4 URL classification and DNS heuristics.",
                },
                {
                  icon: <Network className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "Behavioral Bot Detection",
                  desc: "In-memory per-IP sliding window tracks request rate, timing variance, and repetition patterns — no external model needed.",
                },
                {
                  icon: <TrendingUp className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "Adaptive Weights",
                  desc: "Fusion weights shift between API and Browser contexts. Models that don't run are zeroed and remaining weights renormalize.",
                },
                {
                  icon: <AlertTriangle className="w-5 h-5 text-cyan-400 mt-0.5" />,
                  title: "Hard Rule Overrides",
                  desc: "Malware domains, blocked URLs, payload attacks, and combined bot+traffic signals escalate to Dangerous/Blocked regardless of the fused score.",
                },
              ].map((card) => (
                <div key={card.title} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5">
                  <div className="flex items-start gap-3">
                    {card.icon}
                    <div>
                      <h3 className="text-base font-semibold text-white mb-1">{card.title}</h3>
                      <p className="text-slate-400 text-sm leading-relaxed" dangerouslySetInnerHTML={{ __html: card.desc }} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-12">How It Works</h2>

          <div className="space-y-6">
            {/* Step 1 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold text-sm">1</div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Domain Pre-Filter</h3>
                <p className="text-slate-300 mb-4 text-sm leading-relaxed">
                  Every request URL is checked before any ML model runs. The pipeline short-circuits as early as possible.
                </p>
                <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                  {[
                    { step: "Whitelist",  desc: "16 major domains fast-tracked as safe" },
                    { step: "Blocklist",  desc: "URLhaus / PhishTank / Spamhaus match" },
                    { step: "DNS",        desc: "Non-existent domains flagged immediately" },
                    { step: "Heuristics", desc: "Excessive hyphens, suspicious keywords, depth" },
                  ].map((s) => (
                    <div key={s.step} className="bg-slate-900/50 rounded-lg p-3">
                      <div className="text-cyan-400 font-medium mb-1 text-xs uppercase tracking-wide">{s.step}</div>
                      <div className="text-slate-400 text-xs">{s.desc}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Step 2 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold text-sm">2</div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Feature Extraction</h3>
                <p className="text-slate-300 mb-4 text-sm leading-relaxed">
                  Every HTTP request is converted into a numeric vector. UUID/GUID segments are stripped before entropy scoring
                  to prevent false positives on legitimate REST routes.
                </p>
                <div className="grid md:grid-cols-3 gap-3 text-sm">
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Structural</div>
                    <div className="text-slate-400 text-xs">Request length, URL depth, parameter count</div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Complexity</div>
                    <div className="text-slate-400 text-xs">Special characters, Shannon entropy (UUID-stripped)</div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-cyan-400 font-medium mb-1">Semantic</div>
                    <div className="text-slate-400 text-xs">SQL keywords, script injection patterns</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Step 3 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold text-sm">3</div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Heuristic Payload Detection</h3>
                <p className="text-slate-300 mb-4 text-sm leading-relaxed">
                  Fast heuristic rules run on every request regardless of HTTP method (GET, POST, etc.).
                  A match immediately sets <code className="text-cyan-400 bg-slate-900/60 px-1 rounded text-xs">payload_attack=true</code> and triggers a hard Dangerous override in the fusion engine.
                </p>
                <div className="grid sm:grid-cols-3 gap-3 text-sm">
                  {[
                    { label: "SQL Injection",  cond: "sql_keyword_score > 0" },
                    { label: "XSS Attack",     cond: "script_tag_score > 0" },
                    { label: "Path Traversal", cond: "../, %2e%2e, ..%2f detected" },
                  ].map((h) => (
                    <div key={h.label} className="bg-slate-900/50 rounded-lg p-3">
                      <div className="text-orange-400 font-medium mb-1 text-xs">{h.label}</div>
                      <div className="text-slate-400 font-mono text-xs">{h.cond}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Step 4 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold text-sm">4</div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Parallel Model Execution</h3>
                <p className="text-slate-300 mb-4 text-sm leading-relaxed">
                  All applicable models call in parallel via <code className="text-cyan-400 bg-slate-900/60 px-1 rounded text-xs">asyncio.gather()</code>.
                  Models with missing inputs are skipped — their weights are zeroed and renormalized.
                </p>
                <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                  {[
                    { id: "M1", label: "Payload", source: "HuggingFace", runs: "API + raw request" },
                    { id: "M2", label: "Bot",     source: "HuggingFace", runs: "14 flow features" },
                    { id: "M3", label: "Traffic", source: "HuggingFace", runs: "35 flow features" },
                    { id: "M4", label: "URL",     source: "HuggingFace", runs: "Always (with URL)" },
                  ].map((m) => (
                    <div key={m.id} className="bg-slate-900/50 rounded-lg p-3">
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className="text-cyan-400 font-bold text-xs">{m.id}</span>
                        <span className="text-white font-medium text-xs">— {m.label}</span>
                      </div>
                      <div className="text-slate-500 text-xs">{m.source}</div>
                      <div className="text-slate-400 text-xs mt-1">{m.runs}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Step 5 */}
            <div className="flex gap-4 items-start">
              <div className="flex-shrink-0 w-10 h-10 bg-cyan-500 rounded-full flex items-center justify-center text-white font-bold text-sm">5</div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 flex-1">
                <h3 className="text-xl font-semibold text-white mb-2">Signal Fusion &amp; Verdict</h3>
                <p className="text-slate-300 mb-4 text-sm leading-relaxed">
                  Active signals are combined with renormalized weights. Hard rules are checked first — if matched,
                  thresholds are bypassed entirely.
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
                  {verdicts.map((v) => (
                    <div key={v.label} className={`${v.bg} ${v.border} border rounded-lg p-3`}>
                      <div className={`${v.color} font-semibold text-sm mb-1`}>{v.label}</div>
                      <div className="text-slate-400 font-mono text-xs">{v.range}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Fusion Weights */}
      <section className="py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-4">5-Signal Fusion Weights</h2>
          <p className="text-slate-400 text-center mb-10 text-sm">
            Weights adapt to the request context and renormalize when models are skipped.
          </p>
          <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl overflow-hidden">
            <div className="grid grid-cols-4 bg-slate-900/60 px-6 py-3 text-xs uppercase tracking-widest text-slate-500 font-semibold">
              <span className="col-span-2">Signal</span>
              <span className="text-center">API Weight</span>
              <span className="text-center">Browser Weight</span>
            </div>
            {signals.map((s, i) => (
              <div
                key={s.name}
                className={`grid grid-cols-4 px-6 py-4 items-center ${i < signals.length - 1 ? "border-b border-slate-700/30" : ""}`}
              >
                <div className="col-span-2">
                  <div className="text-white text-sm font-medium">{s.name}</div>
                  <div className="text-slate-500 text-xs mt-0.5">{s.desc}</div>
                </div>
                <div className="text-center text-cyan-400 font-mono text-sm">{s.api}</div>
                <div className="text-center text-cyan-400 font-mono text-sm">{s.browser}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Tech Stack */}
      <section className="py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-12">Technology Stack</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              {
                title: "Backend",
                items: ["Python 3.10+ & FastAPI", "scikit-learn (Isolation Forest, RF)", "Pandas & NumPy", "httpx async client", "motor (MongoDB async)"],
              },
              {
                title: "ML Models",
                items: ["Isolation Forest (base signal)", "M1 Payload — HuggingFace Space", "M2 Bot — HuggingFace Space", "M3 Traffic — HuggingFace Space", "M4 URL — HuggingFace Space"],
              },
              {
                title: "Frontend",
                items: ["Next.js 16 & React 19", "TypeScript", "Tailwind CSS 4", "framer-motion", "Spline 3D"],
              },
              {
                title: "Auth & Data",
                items: ["Firebase Auth", "Google OAuth", "Phone OTP (SMS)", "MongoDB Atlas", "URLhaus / PhishTank / Spamhaus"],
              },
            ].map((col) => (
              <div key={col.title} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">{col.title}</h3>
                <ul className="space-y-2">
                  {col.items.map((item) => (
                    <li key={item} className="flex items-center gap-2 text-slate-300 text-sm">
                      <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
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

      <Footer />
    </div>
  );
}

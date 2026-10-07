"use client";

import React, { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface Indicator {
  category: string;
  severity: string;
  evidence: string;
  description?: string;
}

interface URLSignals {
  is_ip_address: boolean;
  has_suspicious_tld: boolean;
  excessive_subdomains: boolean;
  suspicious_hyphenation: boolean;
  is_punycode: boolean;
  is_shortened: boolean;
  has_credential_path: boolean;
  is_unusually_long: boolean;
  detected_flags: string[];
}

interface URLIntelligence {
  url: string;
  domain: string;
  hostname: string;
  path: string;
  risk_score: number;
  signals: URLSignals;
  brand_similarity?: {
    brand: string;
    score: number;
    potential_impersonation: boolean;
    official_domains: string[];
  };
  reputation_status: string;
}

interface ThreatReport {
  analysis_id: string;
  risk_score: number;
  severity: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  threat_types: string[];
  confidence: number;
  indicators: Indicator[];
  extracted_entities: {
    urls: string[];
    emails: string[];
    phone_numbers: string[];
    organizations: string[];
  };
  explanation: string;
  recommended_actions: string[];
  retrieved_evidence: {
    source: string;
    relevance: number;
    evidence: string;
  }[];
  processing_metadata: {
    analysis_mode: string;
    model_used?: string;
    duration_ms: number;
    timestamp: string;
  };
  attack_chain?: string[];
  url_intelligence?: URLIntelligence;
}

interface FullAnalysisResult {
  input_type: string;
  threat_report: ThreatReport;
  extracted_text?: string;
  ocr_metadata?: {
    provider: string;
    confidence: number | null;
    ocr_duration_ms: number;
  };
  url_intelligence?: URLIntelligence;
  headers?: {
    from_address: string;
    to_address?: string;
    reply_to?: string;
    subject?: string;
    reply_to_mismatch: boolean;
    spf_status: string;
    dkim_status: string;
    dmarc_status: string;
    anomalies: string[];
  };
  attachments?: { filename: string; content_type: string; size_bytes: number }[];
}

const PRESETS = [
  {
    name: "Fake SBI KYC (Phishing)",
    type: "text",
    text: "URGENT! Your SBI account has been suspended due to an unverified KYC status. Complete KYC verification immediately at https://sbi-secure-login.xyz/verify within 24 hours to prevent permanent closure.",
  },
  {
    name: "FedEx Fee Scam",
    type: "text",
    text: "FedEx: Your package delivery has been put on hold due to an incorrect shipping address. Please pay the $2.99 re-delivery fee and update address details at http://fedex-parcel-update.top/tracking.",
  },
  {
    name: "Upfront Job Offer Scam",
    type: "text",
    text: "Part-time job offer! Earn $300 - $800 daily by simply reviewing hotels and rating YouTube videos from home. No experience needed. Pay $50 registration fee to start earning today. WhatsApp +1234567890.",
  },
  {
    name: "Legitimate Bank Statement",
    type: "text",
    text: "Your monthly e-statement for HDFC Bank account ending in 4321 for the period ending March 2026 is now generated. You can view or download it anytime by logging into your official mobile banking app.",
  },
];

export default function Home() {
  const [activeTab, setActiveTab] = useState<"text" | "screenshot" | "url" | "email">("text");
  const [textContent, setTextContent] = useState("");
  const [urlContent, setUrlContent] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePreview, setFilePreview] = useState<string | null>(null);

  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<FullAnalysisResult | null>(null);
  const [showJson, setShowJson] = useState(false);

  const loadingSteps = [
    "Validating input structure & metadata...",
    "Scanning OCR & extracting digital entities...",
    "Evaluating heuristic signals & brand lookalikes...",
    "Retrieving security intelligence citations (RAG)...",
    "Calculating multi-factor risk score...",
    "Synthesizing explainable attack chain...",
  ];

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      if (file.type.startsWith("image/")) {
        setFilePreview(URL.createObjectURL(file));
      } else {
        setFilePreview(null);
      }
    }
  };

  const runAnalysis = async () => {
    setErrorMsg(null);
    setResult(null);
    setLoading(true);
    setLoadingStep(0);

    const stepInterval = setInterval(() => {
      setLoadingStep((prev) => (prev < loadingSteps.length - 1 ? prev + 1 : prev));
    }, 450);

    try {
      if (activeTab === "text") {
        if (!textContent.trim()) throw new Error("Please enter a message or communication snippet.");
        const res = await fetch(`${API_BASE}/api/v1/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: textContent, input_type: "text" }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error?.message || "Analysis request failed.");
        setResult({ input_type: "text", threat_report: data });
      } else if (activeTab === "screenshot") {
        if (!selectedFile) throw new Error("Please select an image screenshot (PNG, JPEG, WEBP <= 10MB).");
        const formData = new FormData();
        formData.append("file", selectedFile);
        const res = await fetch(`${API_BASE}/api/v1/analyze/image`, {
          method: "POST",
          body: formData,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error?.message || "Screenshot analysis failed.");
        setResult(data);
      } else if (activeTab === "url") {
        if (!urlContent.trim()) throw new Error("Please enter a web address or hyperlink.");
        const res = await fetch(`${API_BASE}/api/v1/analyze/url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: urlContent.trim() }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error?.message || "URL analysis failed.");
        setResult(data);
      } else if (activeTab === "email") {
        if (!selectedFile) throw new Error("Please upload an RFC 822 email (.eml) file.");
        const formData = new FormData();
        formData.append("file", selectedFile);
        const res = await fetch(`${API_BASE}/api/v1/analyze/email`, {
          method: "POST",
          body: formData,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data?.error?.message || "Email analysis failed.");
        setResult(data);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to communicate with ScamShield API.");
    } finally {
      clearInterval(stepInterval);
      setLoading(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-400 border-rose-500/40 ring-1 ring-rose-500/30";
      case "HIGH":
        return "bg-orange-500/20 text-orange-400 border-orange-500/40 ring-1 ring-orange-500/30";
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40 ring-1 ring-amber-500/30";
      case "LOW":
        return "bg-blue-500/20 text-blue-300 border-blue-500/40 ring-1 ring-blue-500/30";
      default:
        return "bg-emerald-500/20 text-emerald-400 border-emerald-500/40 ring-1 ring-emerald-500/30";
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8 font-sans">
      {/* Top Header */}
      <header className="flex flex-col md:flex-row md:items-center md:justify-between border-b border-slate-800 pb-5 gap-4">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-indigo-600 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              SCAMSHIELD AI
              <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-mono">
                SOC v0.2.0
              </span>
            </h1>
            <p className="text-xs text-slate-400">Multimodal AI Security Analyst & Threat Intelligence</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-emerald-400">SYSTEM OPERATIONAL</span>
          </div>
          <span className="text-xs text-slate-500 hidden sm:inline">RAG: ACTIVE</span>
        </div>
      </header>

      {/* Main Analysis Input Section */}
      <section className="bg-slate-900/80 rounded-2xl border border-slate-800 p-6 shadow-2xl backdrop-blur-sm space-y-6">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Detect Digital Threats</h2>
          <p className="text-sm text-slate-400">
            Inspect suspicious messages, mobile screenshots, URLs, or email files using AI threat models.
          </p>
        </div>

        {/* Tab Controls */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 bg-slate-950 p-1.5 rounded-xl border border-slate-800">
          <button
            onClick={() => { setActiveTab("text"); setResult(null); }}
            className={`flex items-center justify-center space-x-2 py-2.5 rounded-lg text-xs font-medium transition ${
              activeTab === "text" ? "bg-slate-800 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>📝 Message / Text</span>
          </button>
          <button
            onClick={() => { setActiveTab("screenshot"); setResult(null); }}
            className={`flex items-center justify-center space-x-2 py-2.5 rounded-lg text-xs font-medium transition ${
              activeTab === "screenshot" ? "bg-slate-800 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>📸 Screenshot (OCR)</span>
          </button>
          <button
            onClick={() => { setActiveTab("url"); setResult(null); }}
            className={`flex items-center justify-center space-x-2 py-2.5 rounded-lg text-xs font-medium transition ${
              activeTab === "url" ? "bg-slate-800 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>🌐 Analyze URL</span>
          </button>
          <button
            onClick={() => { setActiveTab("email"); setResult(null); }}
            className={`flex items-center justify-center space-x-2 py-2.5 rounded-lg text-xs font-medium transition ${
              activeTab === "email" ? "bg-slate-800 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>📧 Email (.eml)</span>
          </button>
        </div>

        {/* Presets Bar */}
        {activeTab === "text" && (
          <div className="space-y-2">
            <span className="text-xs text-slate-500 font-mono">DEMO PRESETS:</span>
            <div className="flex flex-wrap gap-2">
              {PRESETS.map((preset, idx) => (
                <button
                  key={idx}
                  onClick={() => setTextContent(preset.text)}
                  className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/60 px-3 py-1.5 rounded-lg transition"
                >
                  ⚡ {preset.name}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input Forms */}
        {activeTab === "text" && (
          <div className="space-y-3">
            <textarea
              rows={4}
              value={textContent}
              onChange={(e) => setTextContent(e.target.value)}
              placeholder="Paste suspicious text message, WhatsApp forward, SMS, or notification here..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
            />
            <div className="flex justify-between items-center text-xs text-slate-500">
              <span>Limit: 20,000 characters</span>
              <span>{textContent.length} chars</span>
            </div>
          </div>
        )}

        {activeTab === "screenshot" && (
          <div className="space-y-4">
            <div className="border-2 border-dashed border-slate-800 hover:border-slate-700 bg-slate-950/60 rounded-xl p-6 text-center space-y-3">
              <input
                type="file"
                accept="image/png,image/jpeg,image/webp"
                onChange={handleFileChange}
                className="hidden"
                id="file-upload"
              />
              <label htmlFor="file-upload" className="cursor-pointer block space-y-2">
                <div className="mx-auto h-12 w-12 rounded-full bg-indigo-500/10 flex items-center justify-center text-indigo-400">
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                  </svg>
                </div>
                <div className="text-sm text-slate-300 font-medium">
                  {selectedFile ? selectedFile.name : "Click to browse or drop screenshot here"}
                </div>
                <div className="text-xs text-slate-500">Supported: PNG, JPG, WEBP (Max 10 MB)</div>
              </label>
            </div>
            {filePreview && (
              <div className="relative max-h-48 overflow-hidden rounded-xl border border-slate-800 bg-slate-950 flex justify-center p-2">
                <img src={filePreview} alt="Preview" className="max-h-44 object-contain rounded-lg" />
              </div>
            )}
          </div>
        )}

        {activeTab === "url" && (
          <div className="space-y-3">
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                🌐
              </span>
              <input
                type="text"
                value={urlContent}
                onChange={(e) => setUrlContent(e.target.value)}
                placeholder="https://sbi-secure-login.xyz/verify or suspicious domain"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl py-3.5 pl-11 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              />
            </div>
            <div className="flex gap-2 text-xs text-slate-500">
              <span>Quick tests:</span>
              <button
                onClick={() => setUrlContent("https://sbi-secure-login.xyz/verify")}
                className="underline hover:text-slate-300"
              >
                sbi-secure-login.xyz
              </button>
              <span>·</span>
              <button
                onClick={() => setUrlContent("https://onlinesbi.sbi")}
                className="underline hover:text-slate-300"
              >
                onlinesbi.sbi (Official)
              </button>
            </div>
          </div>
        )}

        {activeTab === "email" && (
          <div className="space-y-4">
            <div className="border-2 border-dashed border-slate-800 hover:border-slate-700 bg-slate-950/60 rounded-xl p-6 text-center space-y-3">
              <input
                type="file"
                accept=".eml,message/rfc822"
                onChange={handleFileChange}
                className="hidden"
                id="eml-upload"
              />
              <label htmlFor="eml-upload" className="cursor-pointer block space-y-2">
                <div className="mx-auto h-12 w-12 rounded-full bg-indigo-500/10 flex items-center justify-center text-indigo-400">
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                </div>
                <div className="text-sm text-slate-300 font-medium">
                  {selectedFile ? selectedFile.name : "Select an .eml email file to inspect"}
                </div>
                <div className="text-xs text-slate-500">Extracts RFC 822 headers, Reply-To mismatches, SPF/DKIM/DMARC</div>
              </label>
            </div>
          </div>
        )}

        {/* Action Button */}
        <div className="flex items-center justify-between pt-2">
          <button
            onClick={runAnalysis}
            disabled={loading}
            className="w-full sm:w-auto px-8 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 text-white font-medium text-sm rounded-xl transition shadow-lg shadow-indigo-600/20 flex items-center justify-center space-x-2"
          >
            {loading ? (
              <>
                <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                <span>Running Threat Pipeline...</span>
              </>
            ) : (
              <>
                <span>Run Threat Analysis</span>
                <svg className="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                </svg>
              </>
            )}
          </button>
        </div>

        {/* Loading Progress State */}
        {loading && (
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between items-center text-xs font-mono text-slate-400">
              <span className="text-indigo-400 animate-pulse">ANALYSIS IN PROGRESS</span>
              <span>{Math.round(((loadingStep + 1) / loadingSteps.length) * 100)}%</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-indigo-500 h-1.5 transition-all duration-300"
                style={{ width: `${((loadingStep + 1) / loadingSteps.length) * 100}%` }}
              />
            </div>
            <p className="text-xs text-slate-300 font-mono">{loadingSteps[loadingStep]}</p>
          </div>
        )}

        {/* Error Alert */}
        {errorMsg && (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs space-y-1">
            <div className="font-bold flex items-center gap-1.5">
              <span>⚠️</span> Analysis Notice
            </div>
            <p>{errorMsg}</p>
          </div>
        )}
      </section>

      {/* Analysis Results View */}
      {result && result.threat_report && (
        <main className="space-y-6">
          {/* Top Result Banner */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
              <div className="space-y-1">
                <div className="text-xs font-mono text-slate-400">ANALYSIS VERDICT</div>
                <div className="text-2xl font-bold text-white flex items-center gap-3">
                  <span>{result.threat_report.risk_score} / 100</span>
                  <span
                    className={`text-sm px-3 py-1 rounded-full border font-mono font-bold ${getSeverityBadge(
                      result.threat_report.severity
                    )}`}
                  >
                    {result.threat_report.severity} RISK
                  </span>
                </div>
              </div>

              <div className="text-xs text-slate-400 space-y-0.5 text-left md:text-right font-mono">
                <div>MODE: {result.threat_report.processing_metadata.analysis_mode}</div>
                <div>LATENCY: {result.threat_report.processing_metadata.duration_ms} ms</div>
                <div>ID: {result.threat_report.analysis_id.slice(0, 8)}...</div>
              </div>
            </div>

            {/* Categorized Threat Tags */}
            <div className="space-y-2">
              <div className="text-xs font-mono text-slate-400">THREAT CLASSIFICATIONS:</div>
              <div className="flex flex-wrap gap-2">
                {result.threat_report.threat_types.length > 0 ? (
                  result.threat_report.threat_types.map((type, i) => (
                    <span
                      key={i}
                      className="px-3 py-1 bg-slate-800 border border-slate-700 text-rose-300 text-xs font-mono rounded-lg"
                    >
                      🛡️ {type}
                    </span>
                  ))
                ) : (
                  <span className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono rounded-lg">
                    ✓ NO ACTIVE THREATS IDENTIFIED
                  </span>
                )}
              </div>
            </div>

            {/* Executive Explanation */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1.5">
              <div className="text-xs font-mono text-slate-400">EXECUTIVE SECURITY EVALUATION:</div>
              <p className="text-sm text-slate-200 leading-relaxed">{result.threat_report.explanation}</p>
            </div>
          </div>

          {/* SIGNATURE FEATURE: WHY IS THIS DANGEROUS? — ATTACK CHAIN */}
          {result.threat_report.attack_chain && result.threat_report.attack_chain.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
                    ⚡ Why is this Dangerous? — Attack Chain
                  </h3>
                  <p className="text-xs text-slate-400">
                    Step-by-step psychological and technical progression of the detected exploit.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
                {result.threat_report.attack_chain.map((step, idx) => (
                  <div
                    key={idx}
                    className="relative bg-slate-950 border border-slate-800 p-3.5 rounded-xl flex flex-col justify-between"
                  >
                    <div className="text-[10px] font-mono text-indigo-400 font-bold mb-1">STAGE 0{idx + 1}</div>
                    <div className="text-xs font-medium text-slate-200">{step}</div>
                    {idx < (result.threat_report.attack_chain?.length || 0) - 1 && (
                      <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10 text-slate-600 font-mono">
                        ➔
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Screenshot OCR Stepper Diagnostics */}
          {result.input_type === "screenshot" && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-3">
              <h3 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
                📸 Screenshot Processing Telemetry
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs font-mono">
                <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-2.5 rounded-lg text-center">
                  ✓ Image Validated
                </div>
                <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-2.5 rounded-lg text-center">
                  ✓ Text Extracted
                </div>
                <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-2.5 rounded-lg text-center">
                  ✓ Entities Parsed
                </div>
                <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-2.5 rounded-lg text-center">
                  ✓ Signals Scored
                </div>
                <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-2.5 rounded-lg text-center">
                  ✓ Report Ready
                </div>
              </div>
              {result.extracted_text && (
                <div className="mt-3 bg-slate-950 p-3 rounded-xl border border-slate-800 text-xs font-mono text-slate-300">
                  <div className="text-slate-500 mb-1">EXTRACTED OCR TEXT ({result.ocr_metadata?.provider}):</div>
                  <div>"{result.extracted_text}"</div>
                </div>
              )}
            </div>
          )}

          {/* URL Intelligence Diagnostics (if URL inspected or found) */}
          {(result.url_intelligence || result.threat_report.url_intelligence) && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <h3 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
                🌐 URL Intelligence & Brand Impersonation
              </h3>
              {(() => {
                const ui = result.url_intelligence || result.threat_report.url_intelligence!;
                return (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs font-mono">
                      <div className="text-slate-400">DOMAIN ATTRIBUTES:</div>
                      <div>
                        Hostname: <span className="text-slate-200">{ui.hostname}</span>
                      </div>
                      <div>
                        Path: <span className="text-slate-200">{ui.path}</span>
                      </div>
                      <div>
                        URL Risk Score:{" "}
                        <span className={ui.risk_score >= 60 ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                          {ui.risk_score} / 100
                        </span>
                      </div>
                      <div>
                        Reputation: <span className="text-slate-400">{ui.reputation_status}</span>
                      </div>
                    </div>

                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                      <div className="text-slate-400 font-mono">BRAND LOOKALIKE EVALUATION:</div>
                      {ui.brand_similarity ? (
                        <div className="space-y-1">
                          <div className="text-rose-400 font-medium">
                            Potential Impersonation Target: {ui.brand_similarity.brand}
                          </div>
                          <div className="text-slate-400 text-[11px]">
                            Similarity Confidence: {Math.round(ui.brand_similarity.score * 100)}%
                          </div>
                          <div className="text-slate-500 text-[11px]">
                            Official Domains: {ui.brand_similarity.official_domains.join(", ")}
                          </div>
                        </div>
                      ) : (
                        <div className="text-slate-400">No brand lookalike match triggered.</div>
                      )}

                      <div className="pt-2">
                        <div className="text-slate-400 font-mono mb-1">SIGNALS DETECTED:</div>
                        <div className="flex flex-wrap gap-1.5">
                          {ui.signals.detected_flags.length > 0 ? (
                            ui.signals.detected_flags.map((f, i) => (
                              <span key={i} className="px-2 py-0.5 bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] rounded font-mono">
                                ⚠ {f}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-500 font-mono text-[11px]">No suspicious structural flags.</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>
          )}

          {/* Email Forensic Diagnostics */}
          {result.headers && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-3">
              <h3 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
                📧 Email Header Forensic Analysis
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <div className="text-slate-500">FROM SENDER:</div>
                  <div className="text-slate-200 truncate">{result.headers.from_address}</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <div className="text-slate-500">REPLY-TO:</div>
                  <div className="text-slate-200 truncate">{result.headers.reply_to || "None"}</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                  <div className="text-slate-500">REPLY-TO MISMATCH:</div>
                  <div className={result.headers.reply_to_mismatch ? "text-rose-400 font-bold" : "text-emerald-400"}>
                    {result.headers.reply_to_mismatch ? "⚠ DETECTED" : "None"}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Threat Indicators with Grounded Evidence */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
              🔴 Detected Risk Indicators
            </h3>
            <div className="space-y-3">
              {result.threat_report.indicators.length > 0 ? (
                result.threat_report.indicators.map((ind, i) => (
                  <div
                    key={i}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-indigo-400 font-bold">{ind.category}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${getSeverityBadge(ind.severity)}`}>
                        {ind.severity}
                      </span>
                    </div>
                    <div className="text-xs text-rose-300 font-mono bg-rose-500/10 p-2 rounded border border-rose-500/20">
                      "{ind.evidence}"
                    </div>
                    {ind.description && (
                      <p className="text-xs text-slate-400">{ind.description}</p>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-400">No malicious indicators triggered.</div>
              )}
            </div>
          </div>

          {/* Action Panel: WHAT SHOULD YOU DO? */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <h3 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
              🛡️ What Should You Do? — Defensive Guidance
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {result.threat_report.recommended_actions.map((action, i) => {
                const isWarning = action.toLowerCase().includes("not");
                return (
                  <div
                    key={i}
                    className={`p-3.5 rounded-xl border text-xs flex items-start space-x-2.5 ${
                      isWarning
                        ? "bg-rose-500/10 border-rose-500/30 text-rose-200"
                        : "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
                    }`}
                  >
                    <span className="text-base">{isWarning ? "❌" : "✅"}</span>
                    <span className="leading-relaxed">{action}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Security Knowledge Retrieval (RAG Citations) */}
          {result.threat_report.retrieved_evidence.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-3">
              <h3 className="text-sm font-bold tracking-wider text-slate-200 uppercase font-mono">
                📚 Grounded Security Intelligence (RAG Citations)
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {result.threat_report.retrieved_evidence.map((ev, i) => (
                  <div key={i} className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1.5 text-xs">
                    <div className="flex justify-between items-center text-[10px] font-mono text-slate-400">
                      <span className="text-indigo-400">{ev.source}</span>
                      <span>Rel: {ev.relevance}</span>
                    </div>
                    <p className="text-slate-300 text-[11px] line-clamp-3">"{ev.evidence}"</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw JSON Telemetry Toggle */}
          <div className="flex justify-end pt-2">
            <button
              onClick={() => setShowJson(!showJson)}
              className="text-xs text-slate-500 hover:text-slate-300 font-mono underline"
            >
              {showJson ? "Hide Raw JSON Telemetry" : "Inspect Raw JSON Telemetry"}
            </button>
          </div>
          {showJson && (
            <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-[11px] font-mono text-slate-400 overflow-x-auto max-h-96">
              {JSON.stringify(result, null, 2)}
            </pre>
          )}
        </main>
      )}
    </div>
  );
}

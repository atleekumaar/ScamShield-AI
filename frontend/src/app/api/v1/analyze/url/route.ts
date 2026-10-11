import { NextRequest, NextResponse } from "next/server";
import { evaluateURL, processThreatReport } from "@/lib/serverAnalyzer";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const url = body?.url;
    if (!url || typeof url !== "string" || !url.trim()) {
      return NextResponse.json({ error: { message: "URL must not be empty" } }, { status: 422 });
    }

    const backendUrl = process.env.BACKEND_URL;
    if (backendUrl && !backendUrl.includes("localhost")) {
      try {
        const res = await fetch(`${backendUrl}/api/v1/analyze/url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        if (res.ok) {
          const data = await res.json();
          return NextResponse.json(data);
        }
      } catch {
        // fallback
      }
    }

    const urlIntel = evaluateURL(url);
    const threatReport = await processThreatReport(`URL Inspection: ${url}`);
    threatReport.url_intelligence = urlIntel;
    threatReport.risk_score = Math.max(threatReport.risk_score, urlIntel.risk_score);

    return NextResponse.json({
      input_type: "url",
      url_intelligence: urlIntel,
      threat_report: threatReport,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: { message } }, { status: 500 });
  }
}

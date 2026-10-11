import { NextRequest, NextResponse } from "next/server";
import { processThreatReport } from "@/lib/serverAnalyzer";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const content = body?.content;
    if (!content || typeof content !== "string" || !content.trim()) {
      return NextResponse.json({ error: { message: "Content must not be empty" } }, { status: 422 });
    }

    // If external backend is explicitly configured and not localhost on Vercel, try proxying
    const backendUrl = process.env.BACKEND_URL;
    if (backendUrl && !backendUrl.includes("localhost")) {
      try {
        const res = await fetch(`${backendUrl}/api/v1/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        if (res.ok) {
          const data = await res.json();
          return NextResponse.json(data);
        }
      } catch {
        // Fall back to serverAnalyzer
      }
    }

    const report = await processThreatReport(content);
    return NextResponse.json(report);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: { message } }, { status: 500 });
  }
}

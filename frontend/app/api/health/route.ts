import { NextResponse } from "next/server";

// Health endpoint for the frontend container's healthcheck target (INFRA-01).
// Returns HTTP 200; body content is not a contract this phase.
//
// Force static-free dynamic handling so the route is always served live (it
// must respond at runtime, not be cached/prerendered).
export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json({ status: "ok" }, { status: 200 });
}

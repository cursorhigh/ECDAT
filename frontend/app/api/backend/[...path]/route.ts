import { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

function upstreamBase() {
  const configured = process.env.NEXT_PUBLIC_API_BASE_URL || process.env.DJANGO_API_URL || "http://127.0.0.1:8000";
  return configured.replace(/\/+$/, "").replace(/\/api$/, "");
}

function proxyPath(path: string[], search: string) {
  const encodedPath = path.map((segment) => encodeURIComponent(segment)).join("/");
  const lastSegment = path[path.length - 1] || "";
  const suffix = lastSegment.includes(".") ? "" : "/";
  return `${upstreamBase()}/api/${encodedPath}${suffix}${search}`;
}

async function proxy(request: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const headers = new Headers();
  const forwardHeaders = ["accept", "content-type", "cookie", "x-ecdat-session", "x-request-id"];

  for (const name of forwardHeaders) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }

  headers.delete("x-api-key");
  const serverKey = process.env.ECDAT_API_KEY || process.env.DJANGO_API_KEY;
  if (serverKey) headers.set("X-API-Key", serverKey);
  headers.set("X-Request-Id", request.headers.get("x-request-id") || crypto.randomUUID());

  const hasBody = !["GET", "HEAD", "OPTIONS"].includes(request.method);
  const body = hasBody ? await request.arrayBuffer() : undefined;

  try {
    const upstream = await fetch(proxyPath(path, request.nextUrl.search), {
      method: request.method,
      headers,
      body,
      cache: "no-store",
      redirect: "manual"
    });

    const responseHeaders = new Headers();
    const copyHeaders = [
      "content-type",
      "content-disposition",
      "cache-control",
      "pragma",
      "x-request-id",
      "x-frame-options"
    ];
    for (const name of copyHeaders) {
      const value = upstream.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    const setCookie = upstream.headers.get("set-cookie");
    if (setCookie) responseHeaders.set("set-cookie", setCookie);

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders
    });
  } catch {
    return Response.json(
      {
        success: false,
        code: "service_unavailable",
        message: "The ECDAT service is unavailable. Start the workspace service and try again.",
        data: null,
        meta: { request_id: headers.get("x-request-id"), timestamp: new Date().toISOString() }
      },
      { status: 503, headers: { "cache-control": "no-store" } }
    );
  }
}

export async function GET(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export async function POST(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export async function PUT(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export async function DELETE(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

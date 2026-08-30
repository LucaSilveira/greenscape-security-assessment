// workers/edge-gateway/src/index.ts (fixed)
import { verify } from "@tsndr/cloudflare-worker-jwt";

interface Env {
  JWT_PUBLIC_KEY: string;
  JWT_ISSUER: string;   // expected `iss` claim — Worker environment variable, not a secret
  JWT_AUDIENCE: string; // expected `aud` claim — Worker environment variable, not a secret
  INTERNAL_SIGNING_SECRET: string; // Worker secret binding — never in source
}

const ORIGIN = "https://origin.internal.greenscape.com";

const ALLOWED_ORIGINS = new Set([
  "https://app.greenscape.com",
  "https://pro.greenscape.com",
]);

const PROXY_ALLOWLIST = new Set([
  "images.greenscape-cdn.com",
]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    const origin = request.headers.get("Origin");
    const corsOrigin = origin && ALLOWED_ORIGINS.has(origin) ? origin : "";
    const cors = {
      "Access-Control-Allow-Origin": corsOrigin,
      "Access-Control-Allow-Credentials": corsOrigin ? "true" : "false",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Vary": "Origin",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    // Image/link proxy used by the pro app to preview remote URLs — now allowlisted,
    // scheme-restricted, and redirect-safe instead of an open SSRF relay.
    if (url.pathname === "/proxy") {
      const target = url.searchParams.get("url");
      if (!target) return new Response("Missing url", { status: 400 });

      let parsed: URL;
      try {
        parsed = new URL(target);
      } catch {
        return new Response("Invalid url", { status: 400 });
      }

      if (parsed.protocol !== "https:" || !PROXY_ALLOWLIST.has(parsed.hostname)) {
        return new Response("Host not allowed", { status: 403 });
      }

      const upstream = await fetch(parsed.toString(), { redirect: "manual" });
      return new Response(upstream.body, { headers: cors });
    }

    // Verify the JWT signature before trusting anything in its payload. The previous
    // version base64-decoded the payload without ever checking it was actually signed
    // by GreenScape, which let anyone forge an arbitrary `sub` claim.
    const token = (request.headers.get("Authorization") ?? "").replace("Bearer ", "");
    let payload: { sub?: string; iss?: string; aud?: string | string[] };
    try {
      const valid = await verify(token, env.JWT_PUBLIC_KEY, { algorithm: "RS256" });
      if (!valid) return new Response("Unauthorized", { status: 401 });
      payload = JSON.parse(atob(token.split(".")[1]));

      // A valid signature only proves GreenScape's key signed this token — not that it
      // was issued for THIS API. Without an issuer/audience check, a token legitimately
      // signed for a different GreenScape service (sharing the same signing key) would
      // still pass here and be replayable against this Worker.
      const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (payload.iss !== env.JWT_ISSUER || !audiences.includes(env.JWT_AUDIENCE)) {
        return new Response("Unauthorized", { status: 401 });
      }
    } catch {
      return new Response("Unauthorized", { status: 401 });
    }

    const res = await fetch(ORIGIN + url.pathname + url.search, {
      method: request.method,
      headers: {
        ...Object.fromEntries(request.headers),
        "X-User-Id": String(payload.sub ?? ""),
        "X-Internal-Auth": env.INTERNAL_SIGNING_SECRET, // from secret binding, not a source literal
      },
      body: request.method === "GET" ? undefined : request.body,
    });

    return new Response(res.body, { headers: { ...Object.fromEntries(res.headers), ...cors } });
  },
};

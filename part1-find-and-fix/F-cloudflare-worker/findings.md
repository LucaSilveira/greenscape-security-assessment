# Artifact F — `workers/edge-gateway/` + zone config (Cloudflare)

Four findings in the Worker, plus one in the zone config that undermines the point of having Cloudflare in
front of the origin at all.

## Finding F1 — Authentication bypass: JWT payload trusted without signature verification

**Vulnerability class:** Broken Authentication (CWE-347, Improper Verification of Cryptographic Signature).

```ts
const payload = JSON.parse(atob(token.split(".")[1] ?? "e30="));
```

This base64-decodes the JWT payload but **never verifies the signature**. A JWT's payload is not
confidential or tamper-evident on its own — it's only trustworthy once a signature check against a known
key succeeds. Here, anyone can construct a token with an arbitrary `sub` claim (no valid signature needed at
all — the code never calls a verify function), and the Worker forwards it to origin as
`X-User-Id: <attacker-chosen-id>`. **Attacker:** anyone who can send an HTTP request to this Worker — no
valid credential of any kind is required. **Impact:** complete authentication bypass at the edge; the
attacker impersonates any user ID the origin trusts via `X-User-Id`, which — given the origin apparently
treats this header as authoritative identity — means full account takeover for any customer or pro account
by ID.

**Severity: Critical.** This is the single most severe finding in this artifact: it defeats the entire
purpose of having an edge auth layer.

**Fix:** verify the signature before trusting any claim in the token:

```diff
+import { verify } from "@tsndr/cloudflare-worker-jwt";
+
     const token = (request.headers.get("Authorization") ?? "").replace("Bearer ", "");
-    const payload = JSON.parse(atob(token.split(".")[1] ?? "e30="));
+    let payload: { sub?: string; iss?: string; aud?: string | string[] };
+    try {
+      const valid = await verify(token, env.JWT_PUBLIC_KEY, { algorithm: "RS256" });
+      if (!valid) return new Response("Unauthorized", { status: 401 });
+      payload = JSON.parse(atob(token.split(".")[1]));
+
+      const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
+      if (payload.iss !== env.JWT_ISSUER || !audiences.includes(env.JWT_AUDIENCE)) {
+        return new Response("Unauthorized", { status: 401 });
+      }
+    } catch {
+      return new Response("Unauthorized", { status: 401 });
+    }
```

A verified signature only proves the token was signed with GreenScape's key — not that it was issued for
*this* API. Without also checking `iss`/`aud`, a token legitimately issued for a different GreenScape
service that happens to share the same signing key would still pass here and be replayable against this
Worker. `JWT_ISSUER`/`JWT_AUDIENCE` are added as Worker environment variables (not secrets — these values
aren't sensitive, they're just not shown in the original artifact) that the expected values are checked
against.

## Finding F2 — Hardcoded internal shared secret, committed to source

`INTERNAL_SIGNING_SECRET = "gs_edge_9c1f3a7b2e8d4056"` is a literal string in the Worker's source file,
which lives in the same GitHub org as everything else. Anyone with repo read access (or anyone who finds it
in git history after a later "fix") has the shared secret the origin uses to trust requests as having come
through the edge Worker — meaning they can hit `origin.internal.greenscape.com` directly (see F5 — it's not
even hard to reach) with a forged `X-Internal-Auth` header and skip the edge entirely, compounding F1.

**Severity: Critical** — same impact class as F1, via a different path, and it's *already* exposed the
moment this file is committed.

**Fix:** move it to a Worker secret binding, never source:

```diff
-const INTERNAL_SIGNING_SECRET = "gs_edge_9c1f3a7b2e8d4056"; // shared with origin
+// Injected via `wrangler secret put INTERNAL_SIGNING_SECRET` — never in source.
+// Accessed in the handler as `env.INTERNAL_SIGNING_SECRET`.
```

And rotate it — it must be treated as already compromised, since it's been in version control.

## Finding F3 — SSRF via the `/proxy` endpoint

**Vulnerability class:** Server-Side Request Forgery (CWE-918).

```ts
const target = url.searchParams.get("url")!;
const upstream = await fetch(target);
```

This branch runs **before** any auth check in the file, fetches an arbitrary attacker-supplied URL
server-side, and returns the response with permissive CORS headers attached. **Attacker:** anyone who can
reach the Worker's public URL — no authentication required for this path at all. **Impact:** the Worker can
be used to probe/reach internal-network-adjacent hosts (including `origin.internal.greenscape.com` itself),
as an open relay to attack third parties from GreenScape's IP reputation, or as a cost/DoS vector (fetching
large responses through Cloudflare's egress on GreenScape's account). It also functions as an open CORS
proxy for arbitrary content, since it reflects the caller's `Origin` and attaches CORS headers to whatever
it fetches.

**Severity: High.**

**Fix:** allowlist destination hosts, restrict scheme, and disable automatic redirect-following (a common
SSRF-filter bypass):

```diff
+const PROXY_ALLOWLIST = new Set(["images.greenscape-cdn.com"]);
+
     if (url.pathname === "/proxy") {
-      const target = url.searchParams.get("url")!;
-      const upstream = await fetch(target);
+      const target = url.searchParams.get("url");
+      if (!target) return new Response("Missing url", { status: 400 });
+      let parsed: URL;
+      try { parsed = new URL(target); } catch { return new Response("Invalid url", { status: 400 }); }
+      if (parsed.protocol !== "https:" || !PROXY_ALLOWLIST.has(parsed.hostname)) {
+        return new Response("Host not allowed", { status: 403 });
+      }
+      const upstream = await fetch(parsed.toString(), { redirect: "manual" });
       return new Response(upstream.body, { headers: cors });
     }
```

## Finding F4 — Reflected, credentialed, wildcard CORS

**Vulnerability class:** CORS Misconfiguration (CWE-942).

```ts
"Access-Control-Allow-Origin": request.headers.get("Origin") ?? "*",
"Access-Control-Allow-Credentials": "true",
```

Reflecting **any** requesting `Origin` back while also allowing credentialed requests defeats the
same-origin policy entirely: any malicious website can make a victim's browser send a credentialed request
to `api.greenscape.com` through this Worker and read the response cross-origin. **Attacker:** operator of
any website a logged-in GreenScape customer/pro visits. **Impact:** cross-site theft of anything this API
returns for an authenticated session — booking data, PII, whatever `show()`/`search()` (Artifact A) expose.

**Severity: High** (Critical if chained with any of Artifact A's authz gaps — the two compound).

**Fix:** allowlist known frontend origins explicitly; never combine a wildcard/reflected origin with
credentials:

```diff
+const ALLOWED_ORIGINS = new Set(["https://app.greenscape.com", "https://pro.greenscape.com"]);
+
+const origin = request.headers.get("Origin");
+const corsOrigin = origin && ALLOWED_ORIGINS.has(origin) ? origin : "";
 const cors = {
-  "Access-Control-Allow-Origin": request.headers.get("Origin") ?? "*",
-  "Access-Control-Allow-Credentials": "true",
-  "Access-Control-Allow-Headers": "*",
+  "Access-Control-Allow-Origin": corsOrigin,
+  "Access-Control-Allow-Credentials": corsOrigin ? "true" : "false",
+  "Access-Control-Allow-Headers": "Authorization, Content-Type",
+  "Vary": "Origin",
 };
```

## Finding F5 — Zone config: weak TLS, WAF disabled, origin bypasses Cloudflare entirely

**Vulnerability class:** Insecure Transport Config + Origin Exposure (CWE-319, CWE-668).

`zone.tf` sets `ssl = "flexible"` (Cloudflare-to-origin traffic can be plaintext HTTP),
`min_tls_version = "1.0"` (deprecated, fails PCI-DSS Requirement 4.1's TLS 1.2+ floor),
`security_level = "essentially_off"` (disables Cloudflare's WAF/challenge protections), and — most
significantly — `cloudflare_record.api_origin` for `origin.greenscape.com` is `proxied = false`, publishing
a DNS record that points **directly** at the EKS ingress ALB's public IP, unprotected by any of
Cloudflare's WAF, DDoS mitigation, or rate limiting. Anyone who discovers this DNS name (trivial —
`origin.<domain>` is a common enough convention to guess, and it's sitting in a public Terraform file to
begin with) can bypass every edge control the org believes is protecting `api.greenscape.com`, including the
very fixes proposed in F1–F4, by simply hitting the ALB directly.

**Severity: Critical.** This single misconfiguration undermines the value of everything else in this
artifact and in front of the whole platform.

**Fix:**

```diff
 resource "cloudflare_zone_settings_override" "greenscape" {
   zone_id = var.zone_id
   settings {
-    ssl              = "flexible"
-    min_tls_version  = "1.0"
-    security_level   = "essentially_off"
+    ssl              = "full_strict"
+    min_tls_version  = "1.2"
+    security_level   = "medium"
   }
 }

 resource "cloudflare_record" "api_origin" {
   zone_id = var.zone_id
   name    = "origin"
   type    = "A"
   value   = "52.14.207.33"
-  proxied = false
+  proxied = true
 }
```

Also lock the ALB's security group to accept traffic only from Cloudflare's published IP ranges, as
defense-in-depth even with `proxied = true`.

## Severity summary

| # | Issue | Severity | Business impact |
|---|-------|----------|------------------|
| F1 | Unverified JWT trusted for identity | Critical | Full account takeover as any user, no valid credential needed |
| F2 | Hardcoded internal shared secret in source | Critical | Bypasses the edge entirely once leaked (already leaked, by definition) |
| F3 | SSRF via `/proxy`, unauthenticated | High | Internal probing, open relay, cost/DoS |
| F4 | Reflected wildcard + credentialed CORS | High | Cross-site theft of authenticated API responses |
| F5 | `flexible` SSL, TLS 1.0, WAF off, unproxied origin record | Critical | Bypasses every edge control; fails PCI TLS requirement |

## What I'd clear, not flag

The overall shape — a Worker doing edge auth + a small proxy in front of the origin — is a reasonable
architecture; the problems are all in the implementation details (verification, secret handling, allowlists,
zone settings), not the pattern itself. `Access-Control-Allow-Headers: "*"` alone (without the
credentialed-wildcard-origin combination) would only be a low-severity nit; it's flagged as part of F4
because of what it's combined with, not on its own.

## Systemic control

- **Any Worker (or service) decoding a JWT must call a verify function against a known key/JWKS — never
  bare `atob`.** A Semgrep rule matching `atob(.*split\("\."\)\[1\]` with no adjacent `verify(`/`jwtVerify(`
  call in the same function would catch this exact anti-pattern across any other Worker in the fleet.
- **Centralize CORS policy into one shared allowlist**, not hand-rolled per Worker — one wrong Worker
  shouldn't be able to reopen this class of hole.
- **A Terraform policy check (Conftest/OPA against the Cloudflare provider)** failing the build on
  `security_level = "essentially_off"`, `ssl != "full_strict"`, `min_tls_version < "1.2"`, or
  `proxied = false` without an explicit, reviewed exception tag.
- **`gitleaks` (same tool recommended for Artifacts C/D)** would have caught `INTERNAL_SIGNING_SECRET`
  before it was ever committed — this is the same secrets-in-source pattern recurring for the third time
  across six artifacts, which is itself a signal that org-wide secret scanning is the highest-leverage
  single control in Part 1.

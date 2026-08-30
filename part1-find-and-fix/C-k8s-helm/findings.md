# Artifact C — `charts/notification-worker/` (Kubernetes / Helm)

Five findings across the values file and the deployment template. Individually each is a known
Kubernetes/Laravel hardening basic; together, this chart is a template for how to hand an attacker a path
from "compromise one low-value worker pod" to "compromise the EKS node."

## Finding C1 — Plaintext secrets committed in Helm values

**Vulnerability class:** Hardcoded Credentials (CWE-798).

`DATABASE_URL` (with the literal password `Sup3rSecret!`, and pointing at `payout-db.prod`) and
`SENDGRID_API_KEY` are plaintext in `values-prod.yaml`, which — per this stack's own GitOps model
(Helm/ArgoCD, GitHub for all source) — lives in a git repo. Attacker: anyone with read access to the repo
(any engineer, contractor, CI job, or — given this org's AI-agent-heavy workflow — any agent session with
repo read access) gets the production payout DB password and the org's email-sending credentials. The
`SENDGRID_API_KEY` is not a minor leak either: with send access, an attacker can send phishing/BEC email
that looks like it comes from GreenScape's own domain to every customer/pro in the system, which is a brand
and fraud problem on top of a straight breach. And this is literally the same password referenced in
Artifact B's `payout_db` security group, which is open to `0.0.0.0/0` — these two findings chain directly
into "attacker connects to the internet-exposed payout DB with the password found in git."

**Severity: Critical.** Directly enables the worst-case outcome from Artifact B3.

**Fix:** never put secrets in Helm values. Reference a Kubernetes Secret populated out-of-band (External
Secrets Operator pulling from AWS Secrets Manager):

```yaml
# values-prod.yaml (fixed)
env:
  APP_DEBUG: "false"
envFrom:
  - secretRef:
      name: notification-worker-secrets   # populated by External Secrets Operator, never committed
```

## Finding C2 — `APP_DEBUG: "true"` in production

**Vulnerability class:** Sensitive Information Disclosure via Debug Mode (CWE-489).

Laravel debug mode in production renders full stack traces, file paths, environment variables, and query
logs to any user who triggers an unhandled exception. This is a well-known, high-severity Laravel
misconfiguration on its own (`whoops`/Ignition error pages have historically leaked `.env` contents,
including other secrets, and in some framework versions have been chained into RCE). Attacker: any
unauthenticated user who can trigger a 500 (trivial — malformed input to almost any endpoint).

**Severity: High.**

**Fix:** `APP_DEBUG: "false"` (shown above), and see systemic control below — this shouldn't be
overridable per-chart at all.

## Finding C3 — Internal Redis queue exposed via `LoadBalancer` service

**Vulnerability class:** Unauthenticated Network Exposure (CWE-306).

`service.type: LoadBalancer` on port 6379 puts an internet-facing cloud load balancer in front of what the
comment calls "internal redis-backed queue admin." Redis has no auth by default. Attacker: anyone who finds
the LB's public DNS/IP gets full read/write on the notification worker's job queue — they can read queued
job payloads (which may contain customer PII destined for a notification), inject arbitrary jobs (spam
customers, or exploit deserialization in the job consumer), or, depending on Redis configuration, use
`MODULE LOAD`/`CONFIG SET` primitives for further compromise.

**Severity: High.**

**Fix:**

```diff
 service:
-  type: LoadBalancer
+  type: ClusterIP
   port: 6379
```

If Redis genuinely needs to be reached by something outside the cluster, that's a VPN/private-link path with
Redis AUTH enabled — not a public LB on the default port.

## Finding C4 — Privileged, root container with a `hostPath` mount

**Vulnerability class:** Container Escape / Excessive Container Privilege (CWE-250, CWE-269).

`securityContext.privileged: true` + `runAsUser: 0`, on a notification-sending worker that has no
plausible need for host access, plus a `hostPath` volume mounting the **node's** `/etc/ssl/certs` directory
into the container. This is the textbook container-escape setup: if this pod is ever compromised (a
vulnerable npm/composer dependency is the most likely path for a service like this), `privileged: true`
gives it access to host devices and kernel capabilities sufficient to break out to the underlying EKS node.
From the node, an attacker can read the kubelet credentials, other pods' mounted secrets/service-account
tokens on the same node, and the node's IAM role — i.e., this single low-value worker becomes a foothold for
cluster-wide compromise, in a cluster that runs "most workloads" for the company.

**Severity: Critical.** Blast radius is the entire EKS cluster, not just this service.

**Fix:**

```diff
     containers:
       - name: worker
         image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
         securityContext:
-          privileged: true
-          runAsUser: 0
+          privileged: false
+          runAsNonRoot: true
+          runAsUser: 10001
+          readOnlyRootFilesystem: true
+          allowPrivilegeEscalation: false
+          capabilities:
+            drop: ["ALL"]
         envFrom:
           - configMapRef:
               name: {{ .Release.Name }}-env
-        volumeMounts:
-          - name: ca-certs
-            mountPath: /etc/ssl/certs
-            readOnly: true
-      volumes:
-        - name: ca-certs
-          hostPath:
-            path: /etc/ssl/certs
-            type: Directory
+        # Removed: the image's own CA bundle is sufficient. If a custom CA is truly
+        # needed, mount it from a ConfigMap/Secret, never from the host filesystem.
```

## Finding C5 — Mutable `:latest` image tag

**Vulnerability class:** Supply Chain / Non-Reproducible Deploys (CWE-1104-adjacent).

`tag: latest` means the exact code running in prod at any moment is not pinned, can't be reliably scanned
(a scan of `:latest` today says nothing about what's running tomorrow after a silent push), and can't be
rolled back to a known-good version deterministically. This is a lower-severity finding on its own but
compounds every other finding — you cannot answer "which version had the hardcoded secret" without image
pinning.

**Severity: Medium.**

**Fix:** pin to a semantic version or, better, an image digest (`@sha256:...`) produced by the CI pipeline.

## Severity summary

| # | Issue | Severity | Business impact |
|---|-------|----------|------------------|
| C1 | Plaintext DB password + SendGrid key in git | Critical | Feeds directly into B3's internet-exposed DB; email-abuse vector |
| C2 | `APP_DEBUG=true` in prod | High | Stack traces / env leakage to any user who triggers a 500 |
| C3 | Redis queue on public `LoadBalancer` | High | Unauthenticated read/write on job queue |
| C4 | Privileged root container + `hostPath` | Critical | Container escape → EKS node compromise → cluster-wide blast radius |
| C5 | `:latest` image tag | Medium | Non-reproducible, unscannable deploys |

## What I'd clear, not flag

The `volumeMounts`/`readOnly: true` intent on the cert mount is the right instinct (least-privilege on the
mount itself) — the actual problem is the source of the volume (`hostPath` vs. a proper ConfigMap/image CA
bundle), not the read-only flag, which is fine as written and kept in spirit in the fix.

## Systemic control

Every finding here is a Kubernetes/Helm review catching what should be an **admission-time** control,
because a human (or an agent generating a chart from an old example) will eventually produce this exact
pattern again in some other chart:

- **Kyverno or OPA/Gatekeeper cluster-wide policies**, enforced at admission (not just reviewed in PRs):
  deny `privileged: true`, deny `runAsUser: 0`, deny `hostPath` volumes outside an explicit allowlist, deny
  `:latest` tags, require `readOnlyRootFilesystem` and resource limits. This makes the class of bug
  impossible to deploy regardless of who/what wrote the chart.
- **`gitleaks`/`trufflehog` as a pre-commit hook and a CI gate on every repo** — this is exactly the tool
  that catches C1 mechanically; a hardcoded API key or `postgres://user:pass@` connection string matches a
  known secret-scanner signature with no human judgment required.
- **A forced "prod" values overlay** for `APP_DEBUG` and similar prod-safety flags that individual service
  charts cannot override, rather than trusting every chart's author to remember to set it correctly.
- **Default-deny `NetworkPolicy` per namespace**, with explicit allow rules — this would have made C3's
  public `LoadBalancer` mistake far less dangerous even if it shipped, because the queue still wouldn't be
  reachable from anywhere it shouldn't be inside the cluster either.

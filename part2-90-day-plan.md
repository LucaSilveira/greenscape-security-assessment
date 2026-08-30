# GreenScape — 90-Day Security Plan

*For: founder + engineering leadership. Author: Lead Security Engineer (week one).*

This plan assumes the Part 1 artifacts are representative, not exhaustive — six short snippets already
surfaced a critical SQL injection, an authentication bypass at the edge, an internet-exposed production
database, three separate instances of hardcoded secrets in source, an IAM role that can escalate to account
admin, and an AI feature that can be talked into issuing refunds. That pattern density in six small files is
the actual finding of Part 1: the org's baseline hygiene has gaps in every layer of the stack, not one weak
spot. The plan below is sequenced accordingly — stop the parts that are exploitable *today*, then build the
mechanical gates that stop the pattern from recurring, then build the governance that keeps working once I'm
not the one reviewing every diff.

## 1. Top risks, prioritized

Ranked by (likelihood × blast radius) in business terms, not CVSS:

1. **Internet-reachable production data stores and edge bypass.** A payout database open to `0.0.0.0/0`,
   plus a Cloudflare zone record that lets anyone route directly to the origin ALB, bypassing every WAF/edge
   control. This is the only category where *no additional vulnerability is required* — the exposure itself
   is the incident. Combined with hardcoded DB credentials already sitting in Helm values, this is a
   breach that could happen with zero further discovery work by an attacker.
2. **Excessive standing cloud privilege.** An IAM role with `s3:*`/`Resource:*` and unscoped
   `iam:PassRole`. A single compromised workload becomes a path to full AWS account compromise. This is a
   "how bad can one mistake get" risk multiplier sitting under everything else.
3. **Unattended financial risk in the AI support copilot.** A support ticket — the cheapest, most anonymous
   input surface in the product — can currently trigger a real refund with no cap, no human approval, and
   an audit trail that (before fixes) includes the customer's full card number. This is the only risk on
   this list with a direct, automatic path to cash leaving the business, and it will get worse, not better,
   as more agentic features ship on the same unguarded pattern.
4. **Authorization gaps (IDOR/BOLA) across the customer/pro API.** Found in three places in one small
   controller; the reasonable assumption is this recurs across the monolith. Directly exposes customer and
   pro PII and financial data at scale, and it's the kind of bug that gets found by curious users, not just
   attackers — reputational risk on top of the direct exposure.
5. **CI/CD as an open door to production credentials.** `pull_request_target` + `write-all` + unpinned
   third-party actions means anyone who can open a pull request can plausibly walk out with deploy
   credentials. Supply-chain compromise of the pipeline compromises everything the pipeline touches.
6. **Secrets sprawl.** Three separate instances across six artifacts (Helm values, a Cloudflare Worker, and
   implicitly the CI workflow's secret-echoing) of credentials living somewhere they shouldn't. This is a
   *pattern*, and it's the cheapest one to fix mechanically (a secret scanner), which is why it's ranked
   here rather than dead last despite lower per-instance severity than #1–3.
7. **No detection, logging, or compliance evidence trail.** Even after the above are fixed, there is
   currently no way to know if something *does* go wrong (no centralized alerting implied anywhere in the
   scenario), and PCI/SOC2/LGPD are all "aspirational" — meaning zero audit trail exists for any control
   that does get built. Ranked last only because it's a force-multiplier on the others, not a standalone
   incident risk.

**Consciously deprioritized, and why:**

- **Full PCI-DSS/SOC 2 audit engagement.** Both require underlying controls to exist first; hiring an
  assessor now would produce a report documenting exactly the gaps this plan is already fixing, at real
  cost, with no security benefit yet. Revisit at day 90+ once the CI gates and IAM guardrails below are
  live (see Part 3).
- **Exhaustive manual penetration test of every internal service.** Valuable eventually, but Part 1 already
  found more exploitable, fixable issues per hour than a pentest would surface faster than I can act on them
  right now. A scoped external pentest is worth budgeting for once the known issues are closed — testing
  against known-broken infrastructure wastes the tester's time and the budget.
- **Rewriting the entire IAM/Terraform estate to textbook least-privilege.** I'm fixing the roles Part 1
  flagged and adding a gate that stops new instances; a full historical audit of every existing role is a
  60–90+ day project on its own and doesn't reduce risk as fast per hour as closing the known-critical
  findings and shipping the gate that prevents recurrence.
- **Building an in-house SIEM/full detection engineering program.** With a team of one, "ship centralized
  logging with a handful of high-signal alerts" beats "stand up a mature detection platform" — the latter
  is a multi-quarter investment that doesn't fit a 90-day plan without becoming the only thing in it.
- **A formal AI red-team program at full maturity.** Stood up in lightweight form (Part 2B), but a dedicated
  AI security testing practice with rotating red-teamers is a hire, not a 90-day deliverable for a team of
  one.

## 2. Sequencing

**First 2 weeks — stop the bleeding.** Everything here is a known-exploitable finding from Part 1 with a
same-day or same-week fix; no new tooling required, just applying the fixes already written. The network,
IAM, and zone changes below land in Cloud & DevOps's infrastructure, not mine — consistent with them
retaining ownership of day-to-day infra operations (see README): every item that touches production
network/IAM/DNS ships as a PR to them, paired on and reviewed by whoever's on call for that system, not
applied solo just because the fix is already written and correct:

- Close the Postgres security group to the app tier only; rotate the DB password (already leaked via git) —
  paired with Cloud & DevOps, since they're the ones who'll field the page if a legitimate app-tier path gets
  cut off by the SG change.
- Flip the S3 public-access-block back on for `payout-exports`; strip `s3:*`/`Resource:*` and
  `iam:PassRole:*` from the payout service's IAM policy — PR to Cloud & DevOps, run past whoever owns the
  payout service in case something legitimate (an export job, a reporting pipeline) depends on the current
  broad grant and needs a scoped replacement rather than a straight removal.
- Fix the Cloudflare zone: `full_strict` SSL, TLS 1.2 floor, re-enable WAF, set `proxied = true` on the
  origin record — same PR-to-Cloud-&-DevOps model; `full_strict` specifically requires the origin to present
  a valid cert, so this one gets a joint check that origin TLS is actually configured before flipping it, not
  after.
- Rotate the hardcoded Worker signing secret and SendGrid key; move both to proper secret storage — Cloud &
  DevOps executes the rotation (they hold the actual provider consoles/credentials); my job is flagging it's
  compromised and confirming the migration path to Secrets Manager, not doing the rotation unilaterally.
- Ship the `BookingController` fixes (IDOR, SQLi, authz scope, mass assignment) — these are small, isolated
  application-code changes with obvious tests, and go through normal engineering-team code review like any
  other PR.
- Put a hard dollar cap + human-approval-above-threshold on `SupportCopilot`'s refund path *today*, even
  before the full redesign in Part 2B — this is a live financial-fraud vector and the cheapest possible
  interim mitigation (a `min($requested, $cap)` line) buys time for the real fix.
- Switch the PR-preview workflow off `pull_request_target`, drop to least-privilege `permissions`, pin the
  third-party Slack action to a SHA — coordinated with whoever owns the CI pipeline day to day, since a
  `permissions` change can silently break a step that assumed broader access.
- Turn on `gitleaks` in CI, repo-wide, in block mode — find out what else is out there before deciding
  what's next.

*Reasoning:* every item here is high-blast-radius, already exploitable, and cheap. Fix what's on fire before
building the fire code.

**First 30 days — mechanical gates for the classes just fixed.** The Part 1 pattern (agent or human writes
the naive version; nothing stops it from shipping) is the actual root cause, so month one is about making
each fixed class unshippable again, not just fixed once:

- Semgrep (PHP/Laravel + JS/TS rulesets, plus the custom rules from Part 1: raw-SQL interpolation,
  `$request->all()` into mass assignment, a `$fillable` deny-list for sensitive field names) in CI,
  blocking merge.
- Checkov or tfsec on every Terraform PR, blocking merge, for IAM wildcards, public S3, open security
  groups.
- `zizmor`/`actionlint` on every GitHub Actions workflow change.
- Kyverno (or OPA/Gatekeeper) baseline admission policies in EKS: no `privileged: true`, no `runAsUser: 0`,
  no `hostPath` outside an allowlist, no `:latest` tags.
- Stand up an internal AI-call chokepoint (even a thin shared PHP client wrapping the Anthropic call) so
  future LLM features can't skip the redaction/logging/cap pattern the way `SupportCopilot` did — see Part
  2B for the full design; a minimal version ships in 30 days, not 90.
- Migrate the secrets `gitleaks` found in week one into AWS Secrets Manager + External Secrets Operator;
  audit remaining Helm charts for the same pattern.

**Days 30–60 — broaden coverage past the six known artifacts.** Assume the patterns found in Part 1 repeat
elsewhere in the monolith and infra; this phase is about finding out how far:

- Authorization audit across the rest of the Laravel API — every controller method that fetches a model by
  ID gets checked for the `show()`/`search()` pattern from Artifact A. Convert ad hoc `where('customer_id',
  ...)` checks to Laravel Policies as they're found, so the pattern becomes centrally defined.
- Default-deny NetworkPolicies across EKS namespaces; SG-to-SG (not CIDR-based) rules everywhere `0.0.0.0/0`
  or broad CIDRs currently appear.
- IRSA review: one role per service account, no shared "app role"; kill any other `PassRole:*` or
  `s3:*`/`Resource:*` patterns the Checkov gate surfaces on existing (not just new) Terraform.
- Centralized logging (CloudTrail + GuardDuty + Security Hub aggregation at minimum; EKS audit logs
  shipped somewhere queryable) with a first pass of high-signal alerts: IAM policy changes involving
  `PassRole` or wildcards, refund-volume/amount anomalies, WAF/Cloudflare security events.
- GitHub Actions: migrate from long-lived `AWS_ACCESS_KEY_ID`/`SECRET` repo secrets to OIDC federation —
  removes an entire class of "static AWS creds sitting in GitHub" risk in one move.

**Days 60–90 — governance and the AI/agent layer at real depth.** By now the acute fires are out and the
mechanical gates exist; this phase is about the parts that don't get better just because I personally keep
reviewing diffs:

- Full AI gateway rollout per Part 2B (LiteLLM proxy, PII redaction chokepoint, tool-authorization broker,
  eval harness in CI for prompt/system-prompt changes).
- Written, versioned security standards (`SECURITY.md` + `docs/security/`) covering the conventions the CI
  gates already enforce, so they're documented, not just mechanically true.
- CODEOWNERS routing for anything touching authz, `$fillable`/mass assignment, IAM/Terraform, and
  system-prompt/tool-definition files to a named reviewer.
- Decision-rights doc: who approves new IAM permissions, who approves new third-party GitHub Actions, who
  approves new LLM tool/agent capabilities, escalation path for a suspected breach.
- Kick off the PCI scope-reduction project (Part 3) and a lightweight LGPD data-mapping exercise — not full
  audits, but the concrete first steps that make either audit tractable later.
- First incident-response runbook and a tabletop exercise with the Cloud & DevOps team.

*Reasoning behind this order:* blast radius first (things that are exploitable with zero additional work),
then the gates that stop the same classes recurring (cheap, mechanical, compounding value the longer they
run), then breadth (assume Part 1 is a sample, not the full population), then governance (valuable but only
once there's something worth governing). Sequencing by "ease" alone would have front-loaded the CI gates;
sequencing by "blast radius" is why the open database and the refund cap come before any tooling investment.

## 3. Controls to stand up, concretely

- **CI security gate:** Semgrep (SAST, custom Laravel/mass-assignment/raw-SQL rules) + `gitleaks` (secrets)
  + Checkov (Terraform) + `zizmor` (GitHub Actions) + Trivy (container image CVEs), all blocking merge.
  Dependabot stays for known-CVE dependency alerts — it does not and cannot catch business-logic
  authorization bugs, raw SQL, or mass-assignment misconfigurations, which is exactly the gap Part 1
  demonstrated. Named over alternatives (e.g., Snyk, Semgrep's own paid tier) because the open-source tools
  above cover this exact finding set today, have no per-seat cost pressure for a team of one, and Semgrep's
  custom-rule authoring is what lets the org-specific patterns from Part 1 (mass-assignment deny-list,
  raw-SQL-in-Laravel) get codified quickly rather than waiting on a vendor ruleset.
- **IAM/network guardrails:** SCPs at the AWS Organization level denying unscoped `iam:PassRole` and
  disabling of S3 public-access-block; per-service IRSA roles (no shared app role); SG-to-SG network rules
  replacing CIDR-based rules; default-deny Kubernetes NetworkPolicies per namespace; Cloudflare zones
  `full_strict`/TLS 1.2 floor/WAF on by default, origins always `proxied = true`.
- **Detection coverage:** CloudTrail + GuardDuty + Security Hub as the AWS-side baseline (native, minimal
  ops for a team of one); EKS audit logs and Cloudflare security events shipped to the same aggregation
  point; a short, high-signal alert list to start (IAM wildcard/PassRole changes, SG opened to 0.0.0.0/0,
  refund volume/amount anomalies, WAF block-rate spikes) rather than trying to alert on everything at once
  and drowning in noise.
- **Secrets story:** AWS Secrets Manager as the single source of truth; External Secrets Operator syncing
  into Kubernetes (no plaintext in Helm values, ever, enforced by the `gitleaks` CI gate); GitHub Actions
  moved to OIDC federation instead of long-lived IAM user credentials; scheduled rotation for DB credentials
  and third-party API keys.

## 4. Securing AI-agent-authored code

Part 1B is the concrete evidence for the approach here: an agent produced a plausible-looking fix, a human
reviewer approved it, and the patch left a live SQL injection, an unaddressed authorization gap, and
introduced a new mass-assignment vulnerability — in a 20-line diff, with a stated purpose of "fix the
security issues." That is not a reason to slow agents down; it's a reason not to make a human's attention
span the only gate.

- **Don't rely on human review as the primary control — pair every diff (agent- or human-authored) with the
  same mechanical gates from section 3.** A Semgrep rule doesn't get tired at 4pm on a Friday the way a
  junior reviewer does; put the exhaustive, mechanical checks (every raw-SQL variable bound, every
  `$fillable` entry checked against a deny-list) there, and reserve human review for the judgment calls
  those tools can't make (is this authorization boundary actually correct for this business domain).
- **Give agents machine-checkable conventions to target, not prose guidelines.** "Use FormRequest, never
  `$request->all()`" and "authorize via Policies, not inline `where()`" are useful only if a linter enforces
  them — otherwise they're the same tribal knowledge that let this patch through. Publish the conventions
  *as the CI rules*, not as a separate document the agent has no reason to have read.
- **Feed scanner output back into the agent's own loop before a human sees the diff.** A pre-commit/PR step
  that runs Semgrep/Checkov and hands failures back to the coding agent to self-fix means most of the class
  of bug in Part 1B never reaches a human reviewer at all — reducing both risk and reviewer fatigue (which
  is itself a security control: a reviewer who's tired of rubber-stamping obviously-fine diffs will
  eventually rubber-stamp a not-fine one, as happened here).
- **Narrow agents' blast radius by construction.** No standing prod credentials in an agent's working
  context; infra changes from an agent go through the same Terraform plan/PR/apply pipeline as a human's,
  with the same guardrails — agents don't get a side channel to production that bypasses the gates built for
  everyone else.
- **Route risk-weighted diffs to mandatory human review regardless of confidence.** Any diff touching
  authorization, money (`pro_payout_cents`, refunds, pricing), PII fields, `$fillable`/`$guarded`, IAM/
  Terraform, or LLM system prompts/tool definitions requires a named security-trained reviewer via
  CODEOWNERS — independent of whether the author is an agent, a junior, or a senior engineer, and
  independent of how confident the diff "looks." This is the single change that would have stopped Part 1B
  specifically: not "review AI code more carefully," but "this category of file always gets a second,
  specific reviewer."

## 5. Governance that outlives you

The team today is one person (me) plus an informal Cloud & DevOps group with no dedicated security
function. The goal of the next 90 days isn't to personally review everything forever — it's to make most of
what I'd otherwise review either impossible to get wrong (gates) or obviously someone else's clear
responsibility (ownership model):

- **Standards live as enforced CI rules first, documentation second.** A `SECURITY.md`/`docs/security/`
  set exists, but its job is to explain *why* the gates from section 3 exist, not to be the only place the
  rule lives — so a new engineer (or a 2nd/3rd security hire) doesn't have to trust that everyone read the
  doc.
- **Security champions per delivery team, not a central bottleneck.** One trained point-of-contact per
  squad, briefed specifically on the classes Part 1 surfaced (authz, injection, IaC misconfig, AI/agent
  safety) — scales review capacity without requiring a growing security headcount to keep pace with an
  AI-accelerated engineering org.
- **Decision rights, written down:** who can approve a new IAM permission or Terraform exception, who can
  approve a new third-party GitHub Action, who can grant a new LLM tool/agent capability, who owns the
  first hour of incident response. Without this, every edge case escalates to me personally, which doesn't
  scale and doesn't survive me being unavailable.
- **Make secure the default, not the toll booth.** Paved-road templates: a Laravel API-resource-controller
  generator that already wires in a Policy and a FormRequest; a Terraform module for "S3 bucket with the
  correct defaults" that's less code to use than the insecure version; a Helm chart baseline that already
  passes the Kyverno policies. If the secure path is also the fastest path, engineers (and agents) take it
  without being told to — which is the only way this holds up once a 2nd and 3rd engineer join and I'm not
  in every review.
- **Quarterly access reviews** (IAM, GitHub org permissions, LLM tool grants) and a self-serve, lightweight
  threat-modeling template for new features (especially agentic ones) that a delivery team can run without
  me in the room.
- **A small, visible metrics set** (CI security-gate failure rate, count of IAM wildcard grants trending to
  zero, secrets found per month trending to zero, mean time to patch a critical finding) so the org can see
  the program working without me narrating it in every meeting — that visibility is what earns the standing
  to eventually say "no" on something without it reading as arbitrary.

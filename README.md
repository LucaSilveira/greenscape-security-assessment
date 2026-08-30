# GreenScape Security Assessment — Take-Home Submission

## Contents

- `part1-find-and-fix/` — one folder per artifact (A–F), each with `findings.md` (vulnerability class,
  exploit path, severity + business justification, systemic control) and the corrected file(s) as real
  code/config, matching the diffs shown in `findings.md`.
- `part1b-agent-fix-review.md` — review of the proposed agent patch to `BookingController`: what it fixes,
  what it misses (a still-live SQL injection on `status`, no authorization scope in `search()`), what it
  breaks (a new mass-assignment vulnerability via the `$fillable` addition), the corrected version, and the
  gate that stops this class of miss at agent speed.
- `part2-90-day-plan.md` — ranked top risks, 2-week/30/60/90-day sequencing, concrete controls, AI-agent
  code safety, and governance.
- `part2b-ai-agent-security-platform.md` — AI/agent guardrail architecture (Mermaid diagram + bullets)
  covering the gateway, PII guardrails, prompt-injection defense, tool authorization, and detection/evals.
- `part3-compliance.md` — PCI scoping and de-scoping move, the highest-value first compliance step and why,
  audit-readiness without a checkbox factory.
- `part4-ai-in-workflow.md` — honest reflection on AI usage in this assignment, including a real example
  from past work of AI-drafted output being caught and corrected during human review.

## Assumptions made about GreenScape

The scenario is fictional and the artifacts are described as "representative, not exhaustive," so several
assumptions were necessary to give concrete fixes and a concrete plan rather than generic advice:

- The `bookings` table's `customer_id` (and an assumed `pro_id`) are the real ownership boundary for
  authorization — i.e., a customer should only ever see/modify bookings where they're the customer, and the
  same logic would apply symmetrically for a pro-facing equivalent of these endpoints (not shown in the
  artifacts, but implied by "two-sided marketplace").
- `Customer::card_number`/`card_exp` in Artifact E implies the primary application database stores full PAN
  today, rather than a tokenized reference — this materially shapes the Part 3 PCI-scoping answer and the
  Artifact E fix's data-minimization approach.
- The Cloud & DevOps team retains ownership of day-to-day infra operations; this Lead Security Engineer role
  is additive (setting direction, building gates, doing the hands-on fixes that need security judgment), not
  a replacement for that team — the 90-day plan is written assuming their continued involvement, not a
  security team operating in isolation.
- "GreenScape" is assumed to be past its very-early-startup stage (given ~$100M/yr in bookings and three
  brands on one platform) but pre-any-formal-security-function — old enough to have accumulated real
  technical debt across every layer, young enough that a 90-day plan for a team of one is a credible way to
  meaningfully change its risk posture, rather than a rounding error against a much larger existing
  organization.
- Where a specific tool version, IAM ARN, or resource name was needed for a concrete fix but wasn't given in
  the artifact, an illustrative placeholder consistent with the artifact's own naming conventions was used
  (called out explicitly in Part 4) — these need to be swapped for GreenScape's real values before any of
  the Terraform/Helm/Actions snippets are applied as-is.
- Artifact E's `Refunds` service (`issue()`, `alreadyIssuedFor()`, `proposeForApproval()`) is injected but its
  implementation isn't part of the artifact, so its concurrency contract had to be assumed: `issue()` is
  assumed to be the atomicity boundary, inserting under a unique constraint on `refunds.ticket_id` and
  throwing a `RefundAlreadyIssuedException` on conflict, rather than the calling code relying on a
  non-atomic check-then-act. That exception type and constraint are illustrative, consistent with the point
  above — they'd need to exist for real in `App\Services\Refunds` before this file would actually run.
- Artifact F's JWT fix adds an issuer/audience check (`env.JWT_ISSUER`/`env.JWT_AUDIENCE`) that the original
  artifact doesn't define — the artifact only shows the payload being decoded, never what a real GreenScape
  token's `iss`/`aud` claims contain. These are illustrative environment-variable names following the same
  binding pattern as `env.JWT_PUBLIC_KEY`; the real claim values (and whether GreenScape's tokens carry `aud`
  as a string or an array, per the JWT spec's own ambiguity here) need to be confirmed against how tokens are
  actually issued before this check ships.

## What I'd do with more time

Time-boxed to roughly the assignment's target; here's where I drew the line and what the next pass would
cover:

- **Part 1:** I did not attempt to enumerate every possible finding in each artifact — I prioritized the
  ones that move risk (per the assignment's own instruction) and explicitly called out what I cleared rather
  than flagged in each `findings.md`. With more time, I'd run the actual scanners named in each systemic-
  control section (Semgrep, Checkov, zizmor, gitleaks) against these exact snippets to confirm they catch
  what I claimed they'd catch, rather than asserting it from knowledge of the tools.
- **Part 1B:** I'd want to actually run the corrected `Booking` model and controller against a test suite
  (including the "mass-assignment guard" test I proposed) to confirm the fix doesn't break legitimate
  update flows — this review was done by reading the diff, not by executing it.
- **Part 2/2B:** These are directional plans for a fictional org; a real first two weeks would start with
  actually confirming which of the Part 1 findings are real in the live codebase/infra (this assessment
  assumes the six artifacts are representative, which is explicitly stated as an assumption in the
  assignment itself, not something I verified against a real repo).
- **Part 3:** A real PCI scoping exercise needs an actual data-flow diagram of where PAN travels today,
  built with the engineering team, not inferred from six code snippets — this section sketches the right
  first move (tokenization) but isn't a substitute for that exercise.
- **Not attempted, deliberately:** a literal working prototype of the LiteLLM proxy/redaction middleware in
  Part 2B, a full CODEOWNERS file, or actually wiring up the named CI tools (Semgrep/Checkov/zizmor/
  gitleaks) into a real pipeline — Part 2B is a design, not an implementation, consistent with the
  assignment's ask for "a diagram or bullet architecture," and standing up real CI infrastructure is
  explicitly a 30-day item in Part 2's plan, not a take-home deliverable.

## Note on Part 4

The "real work example" bullet in `part4-ai-in-workflow.md` was supplied directly by the candidate (not
drafted by Claude) — an AWS/IAM review where an AI-generated policy suggested two overly broad permissions
that were caught and narrowed during manual verification of the ARNs and actual application behavior. It's
included as-given, since it's the one part of this submission that has to come from the candidate's own
history rather than from the assignment materials.

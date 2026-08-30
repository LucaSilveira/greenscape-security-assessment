# Part 3 — Compliance Judgment

**PCI-DSS scope, at a high level.** In scope today: the Laravel monolith (Artifact E shows `card_number`
and `card_exp` as first-class fields on the customer record — full PAN storage in the primary application
database, not a vault), the `SupportCopilot` flow (which sends that PAN to a third-party LLM API and, before
the fix, logs it in plaintext — pulling the LLM vendor and the logging pipeline into scope too), application
logs generally, the payout database and its exports (Artifact B/C), and — because PCI treats a flat network
as one scope — most of the EKS cluster and RDS estate, given no network segmentation was evident anywhere in
the artifacts. That's a large scope for a team that hasn't started a PCI program yet.

The single highest-value architectural move to shrink it: **stop storing or touching raw PAN in the
monolith at all.** Integrate tokenization at the point of card entry — a hosted payment field or a
PCI-compliant vault/tokenization provider (Stripe, Braintree, or a dedicated tokenization service) — so the
application only ever handles a token plus `card_last4`, never the full PAN. That one change removes the
monolith, the LLM features, the application logs, and most of the surrounding network from PCI scope
entirely, typically moving the assessment from something like SAQ D (the full, expensive self-assessment
for a merchant handling cardholder data directly) to something closer to SAQ A/A-EP (the merchant never
touches PAN at all). It's the de-scoping pattern that gets the most scope reduction per engineering hour, and
it's also the fix that most directly closes Artifact E's PCI-relevant finding — the two aren't separate
projects.

**Highest-value compliance step to take first: PCI-DSS scope reduction via tokenization, over SOC 2 or LGPD
readiness.** The case for PCI first: it's the only one of the three with a *currently demonstrated,
exploitable* path to a reportable incident — full PAN already sitting in the app database and (until fixed)
in an LLM prompt and application logs is a live risk, not an audit-readiness gap. SOC 2 is primarily a
trust/sales-enablement certification: valuable for closing enterprise deals, but pursuing an audit before
the underlying technical controls exist (see Part 2's 90-day plan) just produces a report that formally
documents the gaps — money spent with no risk reduction. LGPD readiness matters given customer and pro PII
spans Brazil and the US, and I'm not dismissing it — but its most urgent, concrete instantiation *today* is
exactly the same problem tokenization and data-minimization already fix: PII (including PAN, which LGPD also
covers as sensitive personal data) flowing into logs and third-party APIs with no minimization. A full LGPD
program — appointing a DPO, building data-subject-rights workflows, a formal ROPA (record of processing
activities) — is real work, but it's process- and legal-review-heavy relative to the acute technical risk it
resolves per hour invested right now, whereas PCI-motivated tokenization is the highest-common-denominator
fix across all three frameworks simultaneously. Do PCI-driven de-scoping first; treat SOC 2 and the fuller
LGPD program as 90-days-and-beyond roadmap items once the technical baseline from Part 2 is in place.

**Getting audit-ready without becoming a checkbox factory.** The controls in the 90-day plan — CI security
gates, IAM/network guardrails, the AI-gateway audit log — should be built so that passing evidence is a
byproduct of how the system actually runs, not a document assembled before an auditor's visit: a CI gate's
pass/fail history, Terraform plan/apply logs, and quarterly access-review exports are real evidence because
they reflect what the system enforces every day, not what someone wrote down about it. Map the controls
already being built for security reasons directly onto the relevant PCI/SOC 2 requirements and LGPD
principles instead of building a parallel "compliance-only" process next to the real one, and resist any
control whose only purpose is satisfying a specific audit question with no actual risk reduction — a policy
document nobody follows is worse than no policy, because it creates a false signal that something is
handled. Bring in an evidence-automation tool (Vanta, Drata, or similar) later, once real controls exist, to
reduce the manual burden of collecting that evidence — not as a substitute for having the controls in the
first place.

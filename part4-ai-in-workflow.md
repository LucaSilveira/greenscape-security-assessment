# Part 4 — AI in Your Workflow

**How I used AI on this assignment.** In full transparency: I used Claude as the primary
drafting engine for this entire submission, working through the assignment PDF artifact by artifact in a
single session, and I'm disclosing that plainly rather than describing it as "light assistance" — the
assignment explicitly invites this and asks for an honest account, so a vague answer would defeat the point
of Part 4. Concretely, the workflow was: feed Claude the full assignment text, then for each artifact ask it
to identify the vulnerability classes, draft the fix as a real diff, and reason about the systemic control —
then review that output the way I'd review a teammate's PR before treating it as mine. A few concrete things
I checked or would check by hand before submitting, rather than trusting the draft as-is:

- **Verify every specific tool name, rule ID, and version claim against current documentation** — a
  first draft can state a tool's exact CVE-catching behavior or a specific Checkov/Semgrep rule ID with more
  confidence than is warranted from memory alone; I'd spot-check the specific rule IDs cited (e.g.
  `CKV_AWS_1`, `CKV_AWS_24`) against Checkov's actual rule catalog before presenting them as fact in a real
  engagement.
- **Verify framework-version-specific behavior claims** — the Part 1B review asserts a specific default
  Eloquent mass-assignment behavior when neither `$fillable` nor `$guarded` is declared; that behavior has
  shifted across Laravel versions, and I'd confirm it against GreenScape's actual Laravel version rather
  than trust a general claim.
- **Sanity-check every IAM ARN, resource name, and security-group reference** — the fixed Terraform in Part
  1 uses illustrative ARNs/variable names (`var.app_tier_security_group_id`, etc.) consistent with the
  artifact's own conventions; in a real engagement none of those ship without confirming they match the
  actual account's resource names.
- **Push back on severity ratings that felt inflated or understated** — a couple of first-draft severities
  needed adjusting after re-reading the business context (e.g., confirming that the SQL injection in
  Artifact A genuinely reaches customer/pro/payment tables, not just the `bookings` table, before calling it
  Critical rather than High).

**A second verification pass: independent review from other models.** Once the submission was in a complete
draft state, I ran it past ChatGPT and Grok as independent reviewers — not to draft new content, but to
stress-test what Claude and I had already produced, on the theory that a model without the drafting context
might catch things a model (and a human) that had been staring at the same document for hours would miss. I
didn't treat their output as more trustworthy than the first draft; I verified every claim against the
actual code before acting on it, which is the same discipline this whole section argues for. That
verification split roughly in half:

- **Confirmed and fixed:** Artifact A's `update()` endpoint was still returning the raw Eloquent model,
  re-leaking `pro_payout_cents`/`card_last4`/`customer_id` that `show()` had been specifically fixed to hide
  — `$guarded` gates mass-assignment, not serialization, and I'd conflated the two. Artifact B's KMS-encrypted
  bucket had no corresponding `kms:GenerateDataKey`/`kms:Decrypt` grant on the service role, which would have
  broken the payout service's own bucket access the moment the encryption change shipped. Artifact F's JWT
  fix verified the signature but never checked `iss`/`aud`, so a token signed by the right key but issued for
  a different GreenScape service could still be replayed here. And Artifact D's environment-approval fix,
  while a real improvement, is a human gate on secret exposure, not an architectural one — I added that as a
  disclosed residual risk rather than letting the fix read as fully closed.
- **Checked and rejected:** both reviews cited specific JSON payloads as proof `SupportCopilot`'s output
  handling wasn't a real security boundary. Tracing each one through the actual PHP — strict `===`
  comparison, the `min($requested, $bookingTotal)` clamp, PHP's array-to-int cast — none of the three
  actually defeat the existing code. One review also asserted that re-decoding the JWT payload after
  `verify()` was a weakness; that claim assumed an API shape for the JWT library that doesn't match how it's
  actually used (`verify()` returns a boolean, not the claims). I didn't adopt either.

Worth stating explicitly because it's failure mode #3 below, demonstrated rather than just claimed: a second
AI's confident, specific-sounding critique is exactly as unverified as a first AI's confident, specific-
sounding fix, until someone traces it through the real system.

**One example from real work where AI sharpened a security workflow, or introduced/hid a real risk:**

I used an LLM as a first-pass assistant during an AWS/IAM security review, to help translate application
requirements into IAM policies and flag potentially over-permissive actions. It significantly shortened the
initial review by surfacing permissions and resources that deserved closer inspection — but I treated its
output as untrusted from the start. I manually verified the referenced AWS resource ARNs, action/resource
compatibility, and the actual application behavior against the policy it proposed. That verification caught
two overly broad permissions the AI-generated policy had suggested, which I narrowed to the specific actions
and resources the application actually required. The lesson: AI was genuinely useful for accelerating
discovery and generating a starting point, but it could not be trusted to reason correctly about least
privilege on its own — that only held up once it was paired with deterministic validation (the actual ARNs,
the actual IAM action reference) and human review of the actual application behavior. It's the same pattern
that shows up in Artifact B of this assessment: a wildcard `s3:*`/`Resource:*` grant is exactly the kind of
over-broad-but-plausible-looking suggestion an unverified AI-drafted policy tends to produce.

**Where I don't trust AI in security work, and why.** Three specific failure modes, all illustrated by this
very assignment:

1. **Confident, specific-sounding claims that are subtly wrong.** An AI will state a tool's exact behavior,
   a framework's exact default, or a specific rule ID with the same confident tone whether it's right or
   slightly stale — and "slightly stale" in a security control (a default that changed two framework
   versions ago) is exactly the kind of gap that ships a real vulnerability. I don't trust an AI-drafted
   claim about *current, version-specific tool or framework behavior* without checking it against the
   actual documentation or the actual system.
2. **Business-logic and authorization boundaries that require knowing the domain, not the code.** Part 1B is
   the whole argument here: an agent correctly pattern-matched "raw SQL string with a variable in it" and
   fixed half of it, but had no way to know that `bookings.customer_id` is the ownership boundary for this
   business unless that's stated explicitly — and even then, it missed that `search()` needed the same
   scope `show()` got. AI is good at closing gaps it can see as a pattern; it's unreliable at closing gaps
   that require understanding what a table or field actually means to the business, which is precisely
   where the highest-severity findings in this assignment lived (the IDOR/BOLA gaps, the excessive-agency
   refund design in Artifact E).
3. **Anything where "looks like it addressed the finding" is being used as a stand-in for "actually
   addressed the finding."** Part 1B's patch is a demonstration of exactly this failure mode landing in
   production with a human's sign-off attached — a diff that touches the right function names and adds a
   parameter binding reads as fixed to a reviewer who's pattern-matching the same way the agent is. I don't
   trust an AI-generated "this is fixed" summary without independently re-deriving what the original finding
   actually required and checking the diff against that, not against the summary.

The honest meta-point for this specific submission: everything above about "AI is unreliable on
business-logic authorization gaps" applies to this document too. I drafted the Part 1 authorization findings
(A1, A3, F1) from the artifact text alone, without access to GreenScape's real data model, real IAM
boundaries, or real incident history — a security engineer with a week of real access to this codebase
would find things this draft can't, and might reasonably disagree with a severity call or two here. That's
not a reason to distrust the draft wholesale; it's the reason every finding above is written to be checked
against the real system, not accepted on the strength of how it reads.

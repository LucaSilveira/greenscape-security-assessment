# Artifact B — `infra/iam/pro-payout-service.tf` (AWS / Terraform)

Three findings, and they compound: an over-privileged role sits in front of a publicly-exposable bucket and
an internet-open database, all in the payout path.

## Finding B1 — `s3:*` on `Resource: "*"` + unscoped `iam:PassRole`

**Vulnerability class:** Excessive IAM Privilege / Privilege Escalation (CWE-269).

**Exploit path:** `pro-payout-service`'s role can act on **every** S3 bucket in the account — not just
payout data — with the full action set (read, write, delete, ACL/policy changes). Worse is
`iam:PassRole` on `Resource: "*"`: this is the canonical AWS privilege-escalation primitive. Whoever can
assume this role (any workload running as this EKS service account, or anything that can exploit a
vulnerability in the payout service itself — a dependency CVE, an SSRF, a deserialization bug) can pass
*any* IAM role in the account to a service they control (e.g., launch an EC2 instance, Lambda, or
ECS/Batch job "as" a far more privileged role). Attacker: whoever compromises the payout service
workload. Payoff: from a single service compromise to full-account lateral movement/escalation, because
this one role is a skeleton key.

**Severity: Critical.** This isn't "the payout service has too much S3 access" — `iam:PassRole:*` means a
compromise of this one service is a plausible path to admin in the AWS account. In an account holding
customer PII, pro banking data, and payment infrastructure, that's the worst-case outcome.

**Fix:**

```diff
 resource "aws_iam_role_policy" "pro_payout_service" {
   name = "pro-payout-service-inline"
   role = aws_iam_role.pro_payout_service.id
   policy = jsonencode({
     Version = "2012-10-17"
     Statement = [
       {
         Sid    = "PayoutData"
         Effect = "Allow"
-        Action = "s3:*"
-        Resource = "*"
+        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
+        Resource = [
+          "arn:aws:s3:::greenscape-payout-exports-prod",
+          "arn:aws:s3:::greenscape-payout-exports-prod/*"
+        ]
       },
-      {
-        Sid    = "RunPayoutJobs"
-        Effect = "Allow"
-        Action = ["iam:PassRole"]
-        Resource = "*"
-      },
+      # iam:PassRole removed: this service does not launch other AWS resources.
+      # If a specific downstream job role genuinely needs to be passed, scope it exactly:
+      # {
+      #   Sid      = "PassSpecificJobRoleOnly"
+      #   Effect   = "Allow"
+      #   Action   = ["iam:PassRole"]
+      #   Resource = aws_iam_role.payout_job_runner.arn
+      #   Condition = { StringEquals = { "iam:PassedToService" = "batch.amazonaws.com" } }
+      # }
+      {
+        # Required by the bucket's SSE-KMS default (see Finding B2) — S3 permissions
+        # alone are not sufficient once the bucket enforces KMS encryption.
+        Sid      = "PayoutDataKMS"
+        Effect   = "Allow"
+        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
+        Resource = var.payout_exports_kms_key_arn
+      },
       {
         Sid      = "ReadPayoutSecrets"
         Effect   = "Allow"
         Action   = ["secretsmanager:GetSecretValue"]
         Resource = "arn:aws:secretsmanager:us-east-1:411:secret:prod/payouts/*"
       }
     ]
   })
 }
```

The `ReadPayoutSecrets` statement is the one clause in this policy that's already scoped correctly (specific
action, specific ARN prefix) — that's the pattern the other two statements should follow, so it's not
flagged as an issue.

## Finding B2 — S3 public-access block explicitly disabled on a payout data bucket

**Vulnerability class:** Sensitive Data Exposure via Cloud Misconfiguration (CWE-284).

`aws_s3_bucket_public_access_block` sets all four flags to `false`, which **removes** the safety net that
prevents this bucket from becoming public via a future ACL or bucket-policy mistake. `greenscape-payout-exports-prod`
almost certainly holds pro banking/payout data by name. Attacker: no attacker needed yet — the finding is
that the one control designed to prevent an *accidental* public exposure (a common, well-documented class of
real-world breach) has been turned off for exactly the bucket that can least afford it. The moment anyone
attaches a permissive bucket policy or an object ACL, this data is internet-readable with no additional
guardrail catching it.

**Severity: Critical** (as a latent exposure) — the blast radius if triggered is a full pro-banking-data
breach, and there is currently zero defense-in-depth against the single mistake that triggers it.

**Fix:**

```diff
 resource "aws_s3_bucket_public_access_block" "payout_exports" {
   bucket                  = aws_s3_bucket.payout_exports.id
-  block_public_acls       = false
-  block_public_policy     = false
-  ignore_public_acls      = false
-  restrict_public_buckets = false
+  block_public_acls       = true
+  block_public_policy     = true
+  ignore_public_acls      = true
+  restrict_public_buckets = true
 }

+resource "aws_s3_bucket_server_side_encryption_configuration" "payout_exports" {
+  bucket = aws_s3_bucket.payout_exports.id
+  rule {
+    apply_server_side_encryption_by_default {
+      sse_algorithm     = "aws:kms"
+      kms_master_key_id = var.payout_exports_kms_key_arn
+    }
+  }
+}
```

SSE-KMS on the bucket is not self-sufficient: it changes every `PutObject`/`GetObject` into a KMS-backed
operation, so the calling role needs `kms:GenerateDataKey` (to write) and `kms:Decrypt` (to read) on that
specific key — granted both in the role's IAM policy (added to the `PayoutData` statement set above as
`PayoutDataKMS`) **and** in the KMS key's own key policy, which must list this role as a permitted principal.
Enabling SSE-KMS without both grants doesn't fail loudly at `terraform apply` — the bucket encrypts fine,
and the break only surfaces the next time the payout service tries to read or write an object and gets
`AccessDenied`, which is a worse failure mode than catching it now.

## Finding B3 — Payout database security group open to `0.0.0.0/0` on port 5432

**Vulnerability class:** Network Exposure of a Data Store (CWE-668).

`payout_db` allows inbound Postgres from the entire internet. This is arguably the single worst finding
across all six artifacts by itself: a production database holding payout/financial data is directly
reachable by anyone on the internet. Combined with Artifact C's hardcoded `DATABASE_URL` password
(`Sup3rSecret!`, committed in Helm values), this isn't hypothetical — an attacker who finds that password
in a leaked repo or CI log can connect **directly**, no VPN, no bastion, no pivot required.

**Severity: Critical.** Attacker: anyone on the internet with the (already-leaked, see Artifact C) DB
password. Impact: direct read/write on the payout database — pro banking details, payout history,
potentially linked payment data.

**Fix:**

```diff
 resource "aws_security_group" "payout_db" {
   name   = "payout-db-sg"
   vpc_id = var.vpc_id
   ingress {
     description = "Postgres"
     from_port   = 5432
     to_port     = 5432
     protocol    = "tcp"
-    cidr_blocks = ["0.0.0.0/0"]
+    security_groups = [var.app_tier_security_group_id]
   }
 }
```

Reference by security group, not CIDR — the app tier's SG membership is the actual trust boundary; a CIDR
range (even a "private" one) doesn't tell you *which* workloads can reach the DB, only *where* they happen to
sit on the network.

## What I'd clear, not flag

The `ReadPayoutSecrets` statement (specific action, specific Secrets Manager ARN prefix) is correctly scoped
and is left unchanged. The role's `assume_role_policy` referencing `data.aws_iam_policy_document.eks_assume`
is the expected IRSA pattern for EKS workloads and isn't itself a finding (assuming that data source is
correctly scoped to the specific service account — worth a quick grep, but not shown here as broken).

## Severity summary

| # | Issue | Severity | Business impact |
|---|-------|----------|------------------|
| B1 | `s3:*`/`Resource:*` + `iam:PassRole:*` | Critical | Single-service compromise → account-wide privilege escalation |
| B2 | S3 public access block disabled | Critical (latent) | One ACL mistake away from a pro-banking-data breach |
| B3 | Postgres SG open to `0.0.0.0/0` | Critical | Internet-direct path to the payout database |

## Systemic control

These three findings are one root cause: Terraform changes for this account are not gated by any automated
policy check, so "make it work" (wildcard IAM, permissive SG, disabled public-access-block) ships as easily
as the correct version.

- **`tfsec`/`Checkov` in the Terraform PR pipeline, blocking merge**, not just commenting. Checkov's built-in
  rules cover exactly these three patterns out of the box: `CKV_AWS_1`/`CKV_AWS_54-57` (S3 public access
  block), `CKV_AWS_24`/`CKV_AWS_260` (SG open to the world on a sensitive port), and several `CKV_AWS_1xx`
  rules for IAM wildcard actions/resources and unscoped `PassRole`. This is precisely the class of bug a
  scanner is deterministic at catching, and it should never reach a human reviewer.
- **An Organization-level SCP** denying `iam:PassRole` without a `iam:PassedToService` condition, and
  denying `s3:PutBucketPublicAccessBlock` calls that would disable the block — defense-in-depth so a
  Terraform review miss (or a manual console change that bypasses Terraform entirely) doesn't become a
  breach on its own.
- **AWS Config rules** (`s3-bucket-public-read-prohibited`, `restricted-common-ports`,
  `iam-policy-no-statements-with-admin-access`) to catch drift — anything applied outside the reviewed
  Terraform path.

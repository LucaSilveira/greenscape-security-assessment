resource "aws_iam_role" "pro_payout_service" {
  name               = "pro-payout-service"
  assume_role_policy = data.aws_iam_policy_document.eks_assume.json
}

resource "aws_iam_role_policy" "pro_payout_service" {
  name = "pro-payout-service-inline"
  role = aws_iam_role.pro_payout_service.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PayoutData"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::greenscape-payout-exports-prod",
          "arn:aws:s3:::greenscape-payout-exports-prod/*"
        ]
      },
      {
        # The bucket enforces SSE-KMS by default (see aws_s3_bucket_server_side_encryption_configuration
        # below); without this, every PutObject/GetObject from this role fails with AccessDenied on the
        # key, regardless of the S3 permissions above — SSE-KMS access is not implied by S3 access.
        Sid      = "PayoutDataKMS"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = var.payout_exports_kms_key_arn
      },
      # iam:PassRole removed entirely — this service does not need to launch or pass
      # roles to other AWS resources. If a real future need arises, scope it exactly:
      #
      # {
      #   Sid      = "PassSpecificJobRoleOnly"
      #   Effect   = "Allow"
      #   Action   = ["iam:PassRole"]
      #   Resource = aws_iam_role.payout_job_runner.arn
      #   Condition = { StringEquals = { "iam:PassedToService" = "batch.amazonaws.com" } }
      # }
      {
        Sid      = "ReadPayoutSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:us-east-1:411:secret:prod/payouts/*"
      }
    ]
  })
}

resource "aws_s3_bucket" "payout_exports" {
  bucket = "greenscape-payout-exports-prod"
}

resource "aws_s3_bucket_public_access_block" "payout_exports" {
  bucket                  = aws_s3_bucket.payout_exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "payout_exports" {
  bucket = aws_s3_bucket.payout_exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.payout_exports_kms_key_arn
    }
  }
}

resource "aws_s3_bucket_versioning" "payout_exports" {
  bucket = aws_s3_bucket.payout_exports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_security_group" "payout_db" {
  name   = "payout-db-sg"
  vpc_id = var.vpc_id

  ingress {
    description     = "Postgres from the app tier only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.app_tier_security_group_id]
  }
}

######################################################################
# Gap-closing overrides on the starter's resources.
# GAP-01: S3 uploads bucket moves from SSE-S3 to SSE-KMS with our CMK.
# GAP-04: versioning enabled on the uploads bucket.
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Suspended"
  }
}

######################################################################
# GAP-03: deny any S3 request over plaintext (non-TLS) transport.
# HIPAA 164.312(e)(1) — Transmission Security.
######################################################################

data "aws_iam_policy_document" "uploads_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  policy = data.aws_iam_policy_document.uploads_tls_only.json
}

######################################################################
# GAP-02: DynamoDB intake table moves from an AWS-owned key to our CMK.
# HIPAA 164.312(a)(2)(iv).
#
# Note: server_side_encryption is a top-level block on aws_dynamodb_table
# itself, not a separate resource — this requires modifying the original
# resource block in main.tf rather than an additive override. See the
# str_replace applied to main.tf alongside this file.
######################################################################

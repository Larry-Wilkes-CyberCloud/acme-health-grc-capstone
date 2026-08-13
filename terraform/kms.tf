######################################################################
# KMS — customer-managed key for PHI at rest.
# Closes GAP-01 (S3) and GAP-02 (DynamoDB): both data stores move from
# AWS-owned/AWS-managed keys to a key this account controls, with
# rotation enabled. HIPAA 164.312(a)(2)(iv).
######################################################################

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI at rest (S3 uploads, DynamoDB intake table)"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name    = "${local.name_prefix}-phi-cmk"
    Purpose = "phi-encryption"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}

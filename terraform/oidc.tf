######################################################################
# AWS OIDC federation for GitHub Actions — no long-lived credentials
# stored anywhere. The pipeline assumes this role via the standard
# GitHub Actions OIDC token exchange. Scoped to this exact repo via
# the sub claim's numeric org/repo IDs (GitHub embeds these, not just
# plain names — see the trust policy condition below).
######################################################################

data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github_actions.certificates[0].sha1_fingerprint]
}

data "aws_iam_policy_document" "github_actions_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:Larry-Wilkes-CyberCloud@93053015/acme-health-grc-capstone@1331299128:*"]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name               = "${local.name_prefix}-grc-gate"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume.json
}

resource "aws_iam_role_policy_attachment" "github_actions_readonly" {
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "github_actions_vault_write" {
  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:GetBucketLocation",
    ]
    resources = [
      aws_s3_bucket.evidence_vault.arn,
      "${aws_s3_bucket.evidence_vault.arn}/*",
    ]
  }
}

resource "aws_iam_role_policy" "github_actions_vault_write" {
  name   = "evidence-vault-write"
  role   = aws_iam_role.github_actions.id
  policy = data.aws_iam_policy_document.github_actions_vault_write.json
}

output "github_actions_role_arn" {
  value = aws_iam_role.github_actions.arn
}

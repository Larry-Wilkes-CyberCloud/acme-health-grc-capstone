# METADATA
# title: S3 uploads bucket must use customer-managed KMS encryption
# description: >
#   Closes GAP-01. The Acme Health uploads bucket stores PHI. Encryption
#   at rest must use a customer-managed KMS key (SSE-KMS), not the
#   AWS-managed SSE-S3 default, so the organization controls key policy,
#   rotation, and audit trail for who can decrypt PHI.
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)"]
#   severity: critical
#   remediation: >
#     Add an aws_s3_bucket_server_side_encryption_configuration resource
#     for the uploads bucket with sse_algorithm = "aws:kms" and
#     kms_master_key_id set to a customer-managed key.
package s3_kms_encryption

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	contains(resource.address, "uploads")

	not has_kms_encryption

	msg := sprintf(
		"HIPAA 164.312(a)(2)(iv): S3 bucket '%s' must use SSE-KMS with a customer-managed key, not the AWS-managed default.",
		[resource.address],
	)
}

# Matched by resource address (static, known at plan time) rather than
# the parent bucket's computed id, which is unresolved on a first-apply
# plan and would otherwise make this check unsatisfiable.
has_kms_encryption if {
	some enc in input.resource_changes
	enc.type == "aws_s3_bucket_server_side_encryption_configuration"
	contains(enc.address, "uploads")
	rule := enc.change.after.rule[_]
	rule.apply_server_side_encryption_by_default[_].sse_algorithm == "aws:kms"
}

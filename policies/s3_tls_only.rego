# METADATA
# title: S3 uploads bucket must deny non-TLS requests
# description: >
#   Closes GAP-03. PHI in transit to/from the uploads bucket must be
#   protected. A bucket policy statement denying requests where
#   aws:SecureTransport is false ensures every request, including from
#   a misconfigured client, is rejected unless it uses HTTPS.
# custom:
#   framework: hipaa
#   controls: ["164.312(e)(1)"]
#   severity: high
#   remediation: >
#     Add an aws_s3_bucket_policy with a Deny statement scoped to
#     s3:* actions where aws:SecureTransport is false.
package s3_tls_only

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	contains(resource.address, "uploads")

	not has_tls_only_policy

	msg := sprintf(
		"HIPAA 164.312(e)(1): S3 bucket '%s' must have a bucket policy denying non-TLS (aws:SecureTransport=false) requests.",
		[resource.address],
	)
}

# Matched by resource address (static, known at plan time) rather than
# the parent bucket's computed id.
has_tls_only_policy if {
	some pol in input.resource_changes
	pol.type == "aws_s3_bucket_policy"
	contains(pol.address, "uploads")
	policy_doc := json.unmarshal(pol.change.after.policy)
	some statement in policy_doc.Statement
	statement.Effect == "Deny"
	condition_denies_insecure_transport(statement)
}

condition_denies_insecure_transport(statement) if {
	statement.Condition.Bool["aws:SecureTransport"] == "false"
}

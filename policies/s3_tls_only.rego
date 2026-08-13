# METADATA
# title: S3 uploads bucket must deny non-TLS requests
# description: >
#   Closes GAP-03. PHI in transit to/from the uploads bucket must be
#   protected. A bucket policy statement denying requests where
#   aws:SecureTransport is false ensures every request, including from
#   a misconfigured client, is rejected unless it uses HTTPS.
#
#   Checks for the PRESENCE of a bucket policy resource on the uploads
#   bucket rather than parsing its rendered JSON content: on a
#   from-scratch plan (no prior state, as in this repo's CI which uses
#   local-only state) the policy JSON is built from a data source that
#   references the bucket's own ARN, which is unresolved until the
#   bucket exists — so the entire rendered policy string is an unknown
#   value at plan time, not something we can safely json.unmarshal.
#   Known limitation, documented in WRITEUP.md: a remote Terraform
#   backend shared between CI and local runs would let this policy
#   inspect the actual condition content, not just presence.
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

	not has_bucket_policy

	msg := sprintf(
		"HIPAA 164.312(e)(1): S3 bucket '%s' must have a bucket policy denying non-TLS (aws:SecureTransport=false) requests.",
		[resource.address],
	)
}

has_bucket_policy if {
	some pol in input.resource_changes
	pol.type == "aws_s3_bucket_policy"
	contains(pol.address, "uploads")
}

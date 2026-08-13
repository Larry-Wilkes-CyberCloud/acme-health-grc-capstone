# METADATA
# title: DynamoDB intake table must use customer-managed KMS encryption
# description: >
#   Closes GAP-02. The intake table stores PHI (submission_id, patient_id,
#   free-text fields). It must be encrypted with a customer-managed KMS
#   key, not the AWS-owned default key, so the organization controls
#   key policy and rotation for PHI at rest.
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)"]
#   severity: critical
#   remediation: >
#     Add a server_side_encryption block to the aws_dynamodb_table
#     resource with enabled = true and kms_key_arn set to a
#     customer-managed key.
package dynamodb_kms_encryption

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_dynamodb_table"

	sse := object.get(resource.change.after, "server_side_encryption", [])
	not sse_uses_cmk(sse)

	msg := sprintf(
		"HIPAA 164.312(a)(2)(iv): DynamoDB table '%s' must have server_side_encryption enabled with a customer-managed KMS key.",
		[resource.address],
	)
}

sse_uses_cmk(sse) if {
	count(sse) > 0
	sse[0].enabled == true
	sse[0].kms_key_arn != ""
	sse[0].kms_key_arn != null
}

# METADATA
# title: S3 uploads bucket must have versioning enabled
# description: >
#   Closes GAP-04. Without versioning, an accidental overwrite or
#   malicious tamper of a PHI attachment is unrecoverable. Versioning
#   is also a prerequisite for meaningful backup/recovery evidence
#   under HIPAA's contingency-plan requirement.
# custom:
#   framework: hipaa
#   controls: ["164.308(a)(7)"]
#   severity: high
#   remediation: >
#     Add an aws_s3_bucket_versioning resource for the uploads bucket
#     with versioning_configuration.status = "Enabled".
package s3_versioning

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	contains(resource.address, "uploads")

	not has_versioning_enabled

	msg := sprintf(
		"HIPAA 164.308(a)(7): S3 bucket '%s' must have versioning enabled to protect PHI from accidental overwrite or tampering.",
		[resource.address],
	)
}

# Matched by resource address (static, known at plan time) rather than
# the parent bucket's computed id.
has_versioning_enabled if {
	some ver in input.resource_changes
	ver.type == "aws_s3_bucket_versioning"
	contains(ver.address, "uploads")
	ver.change.after.versioning_configuration[0].status == "Enabled"
}

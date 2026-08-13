# METADATA
# title: Lambda IAM inline policy must not grant wildcard data-store actions
# description: >
#   Closes GAP-07. The intake Lambda's assumed role previously granted
#   dynamodb:* and s3:* on the PHI data stores — far broader than the
#   handler's actual behavior (PutItem, PutObject only). A compromised
#   or buggy Lambda with wildcard permissions could read, modify, or
#   delete PHI it has no legitimate reason to touch.
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(1)"]
#   severity: critical
#   remediation: >
#     Scope the inline policy's Action lists to only the specific API
#     calls the handler makes (e.g. dynamodb:PutItem, s3:PutObject),
#     never a service-level wildcard like dynamodb:* or s3:*.
package iam_least_privilege

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_iam_role_policy"

	policy_doc := json.unmarshal(resource.change.after.policy)
	some statement in policy_doc.Statement
	some action in wildcard_actions(statement.Action)

	msg := sprintf(
		"HIPAA 164.312(a)(1): IAM policy '%s' grants wildcard action '%s' — scope to specific actions the workload actually performs.",
		[resource.address, action],
	)
}

wildcard_actions(action) := [action] if {
	is_string(action)
	endswith(action, ":*")
}

wildcard_actions(actions) := [a | some a in actions; endswith(a, ":*")] if {
	is_array(actions)
}

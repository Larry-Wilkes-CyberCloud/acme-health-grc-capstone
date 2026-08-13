package iam_least_privilege

import rego.v1

test_deny_when_dynamodb_wildcard if {
	policy_json := json.marshal({"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "arn:aws:dynamodb:us-east-1:123:table/intake"},
	]})

	results := deny with input as {"resource_changes": [
		{
			"address": "aws_iam_role_policy.lambda_inline",
			"type": "aws_iam_role_policy",
			"change": {"after": {"policy": policy_json}},
		},
	]}
	count(results) == 1
}

test_deny_when_s3_wildcard_in_array if {
	policy_json := json.marshal({"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Action": ["s3:*"], "Resource": "arn:aws:s3:::uploads"},
	]})

	results := deny with input as {"resource_changes": [
		{
			"address": "aws_iam_role_policy.lambda_inline",
			"type": "aws_iam_role_policy",
			"change": {"after": {"policy": policy_json}},
		},
	]}
	count(results) == 1
}

test_allow_when_scoped_to_specific_actions if {
	policy_json := json.marshal({"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "arn:aws:dynamodb:us-east-1:123:table/intake"},
		{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::uploads/uploads/*"},
	]})

	results := deny with input as {"resource_changes": [
		{
			"address": "aws_iam_role_policy.lambda_inline",
			"type": "aws_iam_role_policy",
			"change": {"after": {"policy": policy_json}},
		},
	]}
	count(results) == 0
}

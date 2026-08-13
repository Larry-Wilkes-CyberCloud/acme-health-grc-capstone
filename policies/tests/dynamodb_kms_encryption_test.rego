package dynamodb_kms_encryption

import rego.v1

test_deny_when_no_encryption_block if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"change": {"after": {"name": "intake"}},
		},
	]}
	count(results) == 1
}

test_deny_when_encryption_disabled if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"change": {"after": {
				"name": "intake",
				"server_side_encryption": [{"enabled": false, "kms_key_arn": ""}],
			}},
		},
	]}
	count(results) == 1
}

test_allow_when_cmk_encryption_present if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"change": {"after": {
				"name": "intake",
				"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123:key/abc"}],
			}},
		},
	]}
	count(results) == 0
}

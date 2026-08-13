package s3_tls_only

import rego.v1

test_deny_when_no_bucket_policy if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
	]}
	count(results) == 1
}

test_allow_when_tls_only_policy_present if {
	policy_json := json.marshal({"Version": "2012-10-17", "Statement": [{
		"Sid": "DenyInsecureTransport",
		"Effect": "Deny",
		"Action": "s3:*",
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}]})

	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"change": {"after": {
				"bucket": "acme-uploads-abc123",
				"policy": policy_json,
			}},
		},
	]}
	count(results) == 0
}

test_deny_when_policy_missing_tls_condition if {
	policy_json := json.marshal({"Version": "2012-10-17", "Statement": [{
		"Sid": "SomeOtherStatement",
		"Effect": "Allow",
		"Action": "s3:GetObject",
	}]})

	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"change": {"after": {
				"bucket": "acme-uploads-abc123",
				"policy": policy_json,
			}},
		},
	]}
	count(results) == 1
}

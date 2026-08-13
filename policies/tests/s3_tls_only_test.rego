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

test_allow_when_bucket_policy_present if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
		{
			"address": "aws_s3_bucket_policy.uploads",
			"type": "aws_s3_bucket_policy",
			"change": {"after": {"bucket": "acme-uploads-abc123"}},
		},
	]}
	count(results) == 0
}

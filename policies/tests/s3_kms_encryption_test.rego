package s3_kms_encryption

import rego.v1

test_deny_when_no_kms_encryption if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
	]}
	count(results) == 1
}

test_allow_when_kms_encryption_present if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {
				"bucket": "acme-uploads-abc123",
				"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
			}},
		},
	]}
	count(results) == 0
}

test_ignores_non_uploads_buckets if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.trail",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-trail-abc123"}},
		},
	]}
	count(results) == 0
}

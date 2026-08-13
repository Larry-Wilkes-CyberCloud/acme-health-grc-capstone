package s3_versioning

import rego.v1

test_deny_when_no_versioning_resource if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
	]}
	count(results) == 1
}

test_deny_when_versioning_disabled if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"change": {"after": {
				"bucket": "acme-uploads-abc123",
				"versioning_configuration": [{"status": "Suspended"}],
			}},
		},
	]}
	count(results) == 1
}

test_allow_when_versioning_enabled if {
	results := deny with input as {"resource_changes": [
		{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"id": "acme-uploads-abc123"}},
		},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"change": {"after": {
				"bucket": "acme-uploads-abc123",
				"versioning_configuration": [{"status": "Enabled"}],
			}},
		},
	]}
	count(results) == 0
}

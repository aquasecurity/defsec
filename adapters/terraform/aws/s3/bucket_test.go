package s3

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_GetBuckets(t *testing.T) {

	source := `
resource "aws_s3_bucket" "bucket1" {

	
}
`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))

}

func Test_BucketGetACL(t *testing.T) {

	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"
  acl    = "authenticated-read"

  # ... other configuration ...
}`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))
	assert.Equal(t, "authenticated-read", s3.Buckets[0].ACL.Value())

}

func Test_V4BucketGetACL(t *testing.T) {

	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "authenticated-read"
}`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))
	assert.Equal(t, "authenticated-read", s3.Buckets[0].ACL.Value())

}

func Test_BucketGetLogging(t *testing.T) {

	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }
}
`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))
	assert.True(t, s3.Buckets[0].Logging.Enabled.Value())

}

func Test_V4BucketGetLogging(t *testing.T) {

	source := `
resource "aws_s3_bucket" "log_bucket" {
  bucket = "example-log-bucket"

  # ... other configuration ...
}

resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
}

resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.example.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}
`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 2, len(s3.Buckets))
	assert.True(t, s3.Buckets[0].Logging.Enabled.Value())

}

func Test_BucketGetVersioning(t *testing.T) {
	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
  versioning {
    enabled = true
  }
}`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))
	assert.True(t, s3.Buckets[0].Versioning.Enabled.Value())
}

func Test_V4BucketGetVersioning(t *testing.T) {
	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))
	assert.True(t, s3.Buckets[0].Versioning.Enabled.Value())
}

func Test_BucketGetEncryption(t *testing.T) {

	source := `
	resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))
	assert.True(t, s3.Buckets[0].Encryption.Enabled.Value())
}

func Test_V4BucketGetEncryption(t *testing.T) {

	source := `
resource "aws_s3_bucket" "example" {
  bucket = "yournamehere"

  # ... other configuration ...
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.mykey.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
`
	modules := testutil.CreateModulesFromSource(t, source, ".tf")

	s3 := Adapt(modules)

	assert.Equal(t, 1, len(s3.Buckets))
	assert.True(t, s3.Buckets[0].Encryption.Enabled.Value())
}

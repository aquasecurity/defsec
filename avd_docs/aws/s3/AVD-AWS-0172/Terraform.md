
Enable Object-level logging for S3 buckets.

```hcl
resource "aws_s3_bucket" "good_example" {
	bucket = "my-bucket"
}

resource "aws_cloudtrail" "example" {
  event_selector {
    read_write_type           = "ReadOnly" # or "All"
    data_resource {
      type = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.good_example.bucket}/"]
    }
  }
}


```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning


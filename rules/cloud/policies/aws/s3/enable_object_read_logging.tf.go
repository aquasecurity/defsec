package s3

var terraformEnableObjectReadLoggingGoodExamples = []string{
	`
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

`,
}

var terraformEnableObjectReadLoggingBadExamples = []string{
	`
resource "aws_s3_bucket" "bad_example" {
	bucket = "my-bucket"
}
`,
}

var terraformEnableObjectReadLoggingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning`,
}

var terraformEnableObjectReadLoggingRemediationMarkdown = ``

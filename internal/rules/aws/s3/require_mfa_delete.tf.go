package s3

var terraformRequireMFADeleteGoodExamples = []string{
	`
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

resource "aws_s3_bucket_versioning" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
	versioning_configuration {
		status = "Enabled"
		mfa_delete = "Enabled"
	}
}
 `,
}

var terraformRequireMFADeleteBadExamples = []string{
	`
resource "aws_s3_bucket" "example" {
	bucket = "bucket"
}

resource "aws_s3_bucket_versioning" "good_example" {
 	bucket = aws_s3_bucket.example.id
   
	versioning_configuration {
		status = "Enabled"
		mfa_delete = "Disabled"
	}
}
 `,
}

var terraformRequireMFADeleteLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning`,
}

var terraformRequireMFADeleteRemediationMarkdown = ``

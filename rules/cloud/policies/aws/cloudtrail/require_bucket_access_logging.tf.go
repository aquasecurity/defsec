package cloudtrail

var terraformBucketAccessLoggingRequiredGoodExamples = []string{
	`
 resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
   s3_bucket_name = "abcdefgh"
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }

resource "aws_s3_bucket" "good_example" {
	bucket = "abcdefgh"
	logging {
		target_bucket = "target-bucket"
	}
}
 `,
}

var terraformBucketAccessLoggingRequiredBadExamples = []string{
	`
resource "aws_cloudtrail" "bad_example" {
   s3_bucket_name = "abcdefgh"
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
}

resource "aws_s3_bucket" "bad_example" {
	bucket = "abcdefgh"
	
}
 `,
}

var terraformBucketAccessLoggingRequiredLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_logging`,
}

var terraformBucketAccessLoggingRequiredRemediationMarkdown = ``

package cloudtrail

var terraformIncludeGlobalServiceEventsGoodExamples = []string{
	`
 resource "aws_cloudtrail" "good_example" {
   include_global_service_events = true
   s3_bucket_name = "abcdefgh"
 }
 `,
}

var terraformIncludeGlobalServiceEventsBadExamples = []string{
	`
resource "aws_cloudtrail" "bad_example" {
   include_global_service_events = false
   s3_bucket_name = "abcdefgh"
 }
 `,
}

var terraformIncludeGlobalServiceEventsLinks = []string{
	`https://registry.terraform.io/providers/rgeraskin/aws2/latest/docs/resources/cloudtrail#include_global_service_events`,
}

var terraformIncludeGlobalServiceEventsRemediationMarkdown = ``

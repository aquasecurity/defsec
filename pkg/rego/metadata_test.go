package rego

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getEngineMetadata(t *testing.T) {
	inputSchema := map[string]interface{}{
		"terraform": map[string]interface{}{
			"good_examples": `resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }`,
		},
		"cloud_formation": map[string]interface{}{"good_examples": `---
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"`,
		}}

	var testCases = []struct {
		schema string
		want   string
	}{
		{
			schema: "terraform",
			want: `resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }`,
		},
		{schema: "cloud_formation",
			want: `---
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"`},
	}

	for _, tc := range testCases {
		t.Run(tc.schema, func(t *testing.T) {
			var m MetadataRetriever
			em, err := m.getEngineMetadata(tc.schema, inputSchema)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, em.GoodExamples[0])
		})
	}
}

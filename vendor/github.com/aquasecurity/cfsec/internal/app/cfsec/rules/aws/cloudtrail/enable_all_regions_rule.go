package cloudtrail

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/cloudtrail"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{
			`---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: false     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"
`,
		},
		GoodExample: []string{`---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"
`,
		},

		Base: cloudtrail.CheckEnableAllRegions,
	})

}

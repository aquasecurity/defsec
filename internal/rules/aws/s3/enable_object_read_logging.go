package s3

import (
	"fmt"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableObjectReadLogging = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0172",
		Provider:  providers.AWSProvider,
		Service:   "s3",
		ShortCode: "enable-object-read-logging",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"3.11"},
		},
		Summary:    "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets.",
		Impact:     "Difficult/impossible to audit bucket object/data changes.",
		Resolution: "Enable Object-level logging for S3 buckets.",
		Explanation: `
Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html",
		},
		Severity: severity.Low,
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableObjectReadLoggingGoodExamples,
			BadExamples:         terraformEnableObjectReadLoggingBadExamples,
			Links:               terraformEnableObjectReadLoggingLinks,
			RemediationMarkdown: terraformEnableObjectReadLoggingRemediationMarkdown,
		},
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if !bucket.Name.GetMetadata().IsResolvable() {
				continue
			}
			bucketName := bucket.Name.Value()
			var hasReadLogging bool
			for _, trail := range s.AWS.CloudTrail.Trails {
				for _, selector := range trail.EventSelectors {
					if selector.ReadWriteType.EqualTo("WriteOnly") {
						continue
					}
					for _, dataResource := range selector.DataResources {
						if dataResource.Type.NotEqualTo("AWS::S3::Object") {
							continue
						}
						for _, partialARN := range dataResource.Values {
							partial := partialARN.Value()
							if partial == "arn:aws:s3" { // logging for all of s3 is enabled
								hasReadLogging = true
								break
							}
							// the slash is important as it enables logging for objects inside bucket
							if partial == fmt.Sprintf("arn:aws:s3:::%s/", bucketName) {
								hasReadLogging = true
								break
							}
						}
					}
				}
				if hasReadLogging {
					break
				}
			}
			if !hasReadLogging {
				results.Add(
					"Bucket does not have object-level read logging enabled",
					&bucket,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)

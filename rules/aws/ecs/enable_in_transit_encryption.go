package ecs

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "ecs",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "ECS Task Definitions with EFS volumes should use in-transit encryption",
		Impact:      "Intercepted traffic to and from EFS may lead to data loss",
		Resolution:  "Enable in transit encryption when using efs",
		Explanation: `ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html",
			"https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled.Metadata(),
					x.Encryption.Enabled.Value(),
				)
			}
		}
		return
	},
)

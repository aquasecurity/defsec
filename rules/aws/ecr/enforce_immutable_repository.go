package ecr

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnforceImmutableRepository = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "ecr",
		ShortCode:   "enforce-immutable-repository",
		Summary:     "ECR images tags shouldn't be mutable.",
		Impact:      "Image tags could be overwritten with compromised images",
		Resolution:  "Only use immutable images in ECR",
		Explanation: `ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>`,
		Links: []string{ 
			"https://sysdig.com/blog/toctou-tag-mutability/",
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

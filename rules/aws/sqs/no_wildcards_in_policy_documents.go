package sqs

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoWildcardsInPolicyDocuments = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "sqs",
		ShortCode:   "no-wildcards-in-policy-documents",
		Summary:     "AWS SQS policy document has wildcard action statement.",
		Impact:      "SQS policies with wildcard actions allow more that is required",
		Resolution:  "Keep policy scope to the minimum that is required to be effective",
		Explanation: `SQS Policy actions should always be restricted to a specific set.

This ensures that the queue itself cannot be modified or deleted, and prevents possible future additions to queue actions to be implicitly allowed.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html",
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

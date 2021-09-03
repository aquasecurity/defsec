package s3

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccessWithAcl = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "s3",
		ShortCode:   "no-public-access-with-acl",
		Summary:     "S3 Bucket has an ACL defined which allows public access.",
		Impact:      "The contents of the bucket can be accessed publicly",
		Resolution:  "Apply a more restrictive bucket ACL",
		Explanation: `S3 bucket permissions should be set to deny public access unless explicitly required.

Granting write access publicly with <code>public-read-write</code> is especially dangerous as you will be billed for any uploaded files.

Additionally, you should not use the <code>authenticated-read</code> canned ACL, as this provides read access to any authenticated AWS user, not just AWS users within your organisation.`,
		Links: []string{ 
			"https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/",
		},
		Severity: severity.Critical,
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

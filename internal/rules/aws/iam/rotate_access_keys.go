package iam

import (
	"fmt"
	"time"

	"github.com/aquasecurity/defsec/pkg/framework"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"
)

var CheckAccessKeysRotated = rules.Register(
	scan.Rule{
		AVDID:    "AVD-AWS-0146",
		Provider: providers.AWSProvider,
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {"1.4"},
		},
		Service:    "iam",
		ShortCode:  "rotate-access-keys",
		Summary:    "Access keys should be rotated at least every 90 days",
		Impact:     "Compromised keys are more likely to be used to compromise the account",
		Resolution: "Rotate keys every 90 days or less",
		Explanation: `
Regularly rotating your IAM credentials helps prevent a compromised set of IAM access keys from accessing components in your AWS account.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/automatically-rotate-iam-user-access-keys-at-scale-with-aws-organizations-and-aws-secrets-manager.html",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {

		for _, user := range s.AWS.IAM.Users {
			var hasKey bool
			for _, key := range user.AccessKeys {
				if key.Active.IsFalse() {
					continue
				}
				if key.CreationDate.Before(time.Now().Add(-time.Hour * 24 * 90)) {
					days := int(time.Since(key.CreationDate.Value().Add(-time.Hour*24*90)).Hours() / 24)
					if days == 0 {
						days = 1
					}
					results.Add(fmt.Sprintf("User access key '%s' should have been rotated %d day(s) ago", key.AccessKeyId.Value(), days), &user)
					hasKey = true
				}
			}
			if !hasKey {
				results.AddPassed(&user)
			}
		}

		return
	},
)

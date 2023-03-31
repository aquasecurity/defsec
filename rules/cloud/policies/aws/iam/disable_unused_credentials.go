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

var CheckUnusedCredentialsDisabled = rules.Register(
	scan.Rule{
		AVDID:    "AVD-AWS-0144",
		Provider: providers.AWSProvider,
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {"1.3"},
		},
		Service:    "iam",
		ShortCode:  "disable-unused-credentials",
		Summary:    "Credentials which are no longer used should be disabled.",
		Impact:     "Leaving unused credentials active widens the scope for compromise.",
		Resolution: "Disable credentials which are no longer used.",
		Explanation: `
CIS recommends that you remove or deactivate all credentials that have been unused in 90 days or more. Disabling or removing unnecessary credentials reduces the window of opportunity for credentials associated with a compromised or abandoned account to be used.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {

		for _, user := range s.AWS.IAM.Users {
			if user.HasLoggedIn() && user.LastAccess.Before(time.Now().Add(-90*24*time.Hour)) {
				results.Add("User has not logged in for >90 days", &user)
				continue
			}
			var hasKey bool
			for _, key := range user.AccessKeys {
				if key.Active.IsFalse() || !key.LastAccess.GetMetadata().IsResolvable() ||
					key.LastAccess.After(time.Now().Add(-90*24*time.Hour)) {
					continue
				}
				results.Add(fmt.Sprintf("User access key '%s' has not been used in >90 days", key.AccessKeyId.Value()), &user)
				hasKey = true
			}
			if !hasKey {
				results.AddPassed(&user)
			}
		}

		return
	},
)

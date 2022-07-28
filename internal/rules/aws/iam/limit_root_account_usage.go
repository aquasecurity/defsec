package iam

import (
	"time"

	"github.com/aquasecurity/defsec/pkg/framework"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"
)

var checkLimitRootAccountUsage = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0140",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "limit-root-account-usage",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"1.1"},
		},
		Summary:    "The \"root\" account has unrestricted access to all resources in the AWS account. It is highly\nrecommended that the use of this account be avoided.",
		Impact:     "Compromise of the root account compromises the entire AWS account and all resources within it.",
		Resolution: "Use lower privileged accounts instead, so only required privileges are available.",
		Explanation: `
The root user has unrestricted access to all services and resources in an AWS account. We highly recommend that you avoid using the root user for daily tasks. Minimizing the use of the root user and adopting the principle of least privilege for access management reduce the risk of accidental changes and unintended disclosure of highly privileged credentials.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, user := range s.AWS.IAM.Users {
			if user.Name.EqualTo("root") {
				if user.LastAccess.After(time.Now().Add(-time.Hour * 24)) {
					results.Add("The root user logged in within the last 24 hours", user.LastAccess)
				} else {
					results.AddPassed(&user)
				}
				break
			}
		}
		return
	},
)

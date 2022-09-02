package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var checkRootHardwareMFAEnabled = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0165",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "enforce-root-hardware-mfa",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"1.6"},
		},
		Summary:    "The \"root\" account has unrestricted access to all resources in the AWS account. It is highly\nrecommended that this account have hardware MFA enabled.",
		Impact:     "Compromise of the root account compromises the entire AWS account and all resources within it.",
		Resolution: "Enable hardware MFA on the root user account.",
		Explanation: `
Hardware MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and password and for an authentication code from their AWS MFA device.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, user := range s.AWS.IAM.Users {
			if user.Name.EqualTo("root") {
				if len(user.MFADevices) == 0 {
					results.Add("Root user does not have a hardware MFA device", &user)
				} else {
					var hasHardware bool
					for _, device := range user.MFADevices {
						if device.IsVirtual.IsFalse() {
							hasHardware = true
							break
						}
					}
					if !hasHardware {
						results.Add("Root user does not have a hardware MFA device", &user)
					} else {
						results.AddPassed(&user)
					}
				}
			}
		}
		return
	},
)

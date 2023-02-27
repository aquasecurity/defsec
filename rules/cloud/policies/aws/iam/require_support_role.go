package iam

import (
	"github.com/aquasecurity/defsec/pkg/framework"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"
)

var CheckRequireSupportRole = rules.Register(
	scan.Rule{
		AVDID:    "AVD-AWS-0169",
		Provider: providers.AWSProvider,
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"1.17"},
		},
		Service:    "iam",
		ShortCode:  "require-support-role",
		Summary:    "Missing IAM Role to allow authorized users to manage incidents with AWS Support.",
		Impact:     "Incident management is not possible without a support role.",
		Resolution: "Create an IAM role with the necessary permissions to manage incidents with AWS Support.",
		Explanation: `
By implementing least privilege for access control, an IAM Role will require an appropriate
IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {

		for _, role := range s.AWS.IAM.Roles {
			for _, policy := range role.Policies {
				if policy.Builtin.IsTrue() && policy.Name.EqualTo("AWSSupportAccess") {
					results.AddPassed(&role)
					return
				}
			}
		}

		results.Add("Missing IAM support role.", defsecTypes.NewUnmanagedMetadata())
		return results
	},
)

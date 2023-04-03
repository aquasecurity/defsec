package iam

import (
	"github.com/aquasecurity/defsec/pkg/framework"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"

	"github.com/aquasecurity/defsec/pkg/types"
)

var FilterIamPassRole = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0342",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "filter-passrole-access",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"1.1"},
			framework.CIS_AWS_1_4: {"1.7"},
		},
		Summary:    "To configure many AWS services, you must pass an IAM role to the service. \nThis allows the service to assume the role later and perform actions on your behalf. \nif there is no check it will escalate privileges.",
		Impact:     "Compromise on security of aws resources.",
		Resolution: "Change and in permission of the role and resources.",
		Explanation: `
       When a service that needs to perform other actions is used (user, role, human, code, or service), the AWS architecture frequently has that service assume an AWS role to carry out the other actions, the service carrying out the actions is "provided" a role by the calling principal and implicitly takes on that role to carry out the actions (instead of executing sts:AssumeRole).
       The privileges attached to the role are distinct from those of the primary ordering the action and may even be larger and can cause security issues.
           `,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		// for _, role := range s.AWS.IAM.Roles {
		var passrole string
		var policyname types.StringValue
		for _, policy := range s.AWS.IAM.Policies {
			document, _ := policy.Document.Parsed.Statements()
			for _, actions := range document {
				search_iam_string, _ := actions.Actions()
				for _, string_property := range search_iam_string {
					if string_property == "iam:PassRole" {
						passrole = string_property
						policyname = policy.Name
						// fmt.Printf("this is %T", Policyname)
					}
				}
			}
		}
		// }
		if passrole == "iam:PassRole" {
			results.Add("Warning: Iam Pass Role is present in the policy", policyname)
		} else {
			results.AddPassed(&policyname)
		}
		return
	},
)

package compute

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckSecurityGroupHasDescription = rules.Register(
	rules.Rule{
		AVDID:       "AVD-OPNSTK-0005",
		Provider:    providers.OpenStackProvider,
		Service:     "networking",
		ShortCode:   "describe-security-group",
		Summary:     "Missing description for security group.",
		Impact:      "Auditing capability and awareness limited.",
		Resolution:  "Add descriptions for all security groups",
		Explanation: `Security groups should include a description for auditing purposes. Simplifies auditing, debugging, and managing security groups.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformSecurityGroupHasDescriptionGoodExamples,
			BadExamples:         terraformSecurityGroupHasDescriptionBadExamples,
			Links:               terraformSecurityGroupHasDescriptionLinks,
			RemediationMarkdown: terraformSecurityGroupHasDescriptionRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, group := range s.OpenStack.Networking.SecurityGroups {
			if group.IsUnmanaged() {
				continue
			}
			if group.Description.IsEmpty() {
				results.Add(
					"Security group rule allows egress to multiple public addresses.",
					group.Description,
				)
			} else {
				results.AddPassed(group)
			}
		}
		return
	},
)

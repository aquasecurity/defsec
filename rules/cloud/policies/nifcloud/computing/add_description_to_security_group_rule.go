package computing

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAddDescriptionToSecurityGroupRule = rules.Register(
	scan.Rule{
		AVDID:      "AVD-NIF-0003",
		Aliases:    []string{"nifcloud-computing-add-description-to-security-group-rule"},
		Provider:   providers.NifcloudProvider,
		Service:    "computing",
		ShortCode:  "add-description-to-security-group-rule",
		Summary:    "Missing description for security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups rules",
		Explanation: `Security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://pfs.nifcloud.com/help/fw/rule_new.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToSecurityGroupRuleGoodExamples,
			BadExamples:         terraformAddDescriptionToSecurityGroupRuleBadExamples,
			Links:               terraformAddDescriptionToSecurityGroupRuleLinks,
			RemediationMarkdown: terraformAddDescriptionToSecurityGroupRuleRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Nifcloud.Computing.SecurityGroups {
			for _, rule := range append(group.EgressRules, group.IngressRules...) {
				if rule.Description.IsEmpty() {
					results.Add(
						"Security group rule does not have a description.",
						rule.Description,
					)
				} else {
					results.AddPassed(&rule)
				}
			}

		}
		return
	},
)

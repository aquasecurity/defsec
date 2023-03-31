package nas

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAddDescriptionToNASSecurityGroup = rules.Register(
	scan.Rule{
		AVDID:      "AVD-NIF-0015",
		Aliases:    []string{"nifcloud-nas-add-description-to-nas-security-group"},
		Provider:   providers.NifcloudProvider,
		Service:    "nas",
		ShortCode:  "add-description-to-nas-security-group",
		Summary:    "Missing description for nas security group.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all nas security groups",
		Explanation: `NAS security groups should include a description for auditing purposes.

Simplifies auditing, debugging, and managing nas security groups.`,
		Links: []string{
			"https://pfs.nifcloud.com/help/nas/fw_new.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToNASSecurityGroupGoodExamples,
			BadExamples:         terraformAddDescriptionToNASSecurityGroupBadExamples,
			Links:               terraformAddDescriptionToNASSecurityGroupLinks,
			RemediationMarkdown: terraformAddDescriptionToNASSecurityGroupRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Nifcloud.NAS.NASSecurityGroups {
			if group.Metadata.IsUnmanaged() {
				continue
			}
			if group.Description.IsEmpty() {
				results.Add(
					"NAS security group does not have a description.",
					group.Description,
				)
			} else if group.Description.EqualTo("Managed by Terraform") {
				results.Add(
					"NAS security group explicitly uses the default description.",
					group.Description,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)

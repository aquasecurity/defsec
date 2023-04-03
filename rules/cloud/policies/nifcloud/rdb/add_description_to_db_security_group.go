package rdb

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAddDescriptionToDBSecurityGroup = rules.Register(
	scan.Rule{
		AVDID:      "AVD-NIF-0012",
		Aliases:    []string{"nifcloud-rdb-add-description-to-db-security-group"},
		Provider:   providers.NifcloudProvider,
		Service:    "rdb",
		ShortCode:  "add-description-to-db-security-group",
		Summary:    "Missing description for db security group.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all db security groups",
		Explanation: `DB security groups should include a description for auditing purposes.

Simplifies auditing, debugging, and managing db security groups.`,
		Links: []string{
			"https://pfs.nifcloud.com/help/rdb/fw_new.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToDBSecurityGroupGoodExamples,
			BadExamples:         terraformAddDescriptionToDBSecurityGroupBadExamples,
			Links:               terraformAddDescriptionToDBSecurityGroupLinks,
			RemediationMarkdown: terraformAddDescriptionToDBSecurityGroupRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Nifcloud.RDB.DBSecurityGroups {
			if group.Metadata.IsUnmanaged() {
				continue
			}
			if group.Description.IsEmpty() {
				results.Add(
					"DB security group does not have a description.",
					group.Description,
				)
			} else if group.Description.EqualTo("Managed by Terraform") {
				results.Add(
					"DB security group explicitly uses the default description.",
					group.Description,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)

package rdb

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicDbAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0008",
		Provider:    providers.NifcloudProvider,
		Service:     "rdb",
		ShortCode:   "no-public-db-access",
		Summary:     "A database resource is marked as publicly accessible.",
		Impact:      "The database instance is publicly accessible",
		Resolution:  "Set the database to not be publicly accessible",
		Explanation: `Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.`,
		Links: []string{
			"https://pfs.nifcloud.com/guide/rdb/server_new.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicDbAccessGoodExamples,
			BadExamples:         terraformNoPublicDbAccessBadExamples,
			Links:               terraformNoPublicDbAccessLinks,
			RemediationMarkdown: terraformNoPublicDbAccessRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Nifcloud.RDB.DBInstances {
			if instance.PublicAccess.IsTrue() {
				results.Add(
					"Instance is exposed publicly.",
					instance.PublicAccess,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)

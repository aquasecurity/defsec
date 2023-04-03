package nas

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoCommonPrivateNASInstance = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0013",
		Aliases:     []string{"nifcloud-nas-no-common-private-nas-instance"},
		Provider:    providers.NifcloudProvider,
		Service:     "nas",
		ShortCode:   "no-common-private-nas-instance",
		Summary:     "The nas instance has common private network",
		Impact:      "The common private network is shared with other users",
		Resolution:  "Use private LAN",
		Explanation: `When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.`,
		Links: []string{
			"https://pfs.nifcloud.com/service/plan.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoCommonPrivateNASInstanceGoodExamples,
			BadExamples:         terraformNoCommonPrivateNASInstanceBadExamples,
			Links:               terraformNoCommonPrivateNASInstanceLinks,
			RemediationMarkdown: terraformNoCommonPrivateNASInstanceRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Nifcloud.NAS.NASInstances {
			if instance.NetworkID.EqualTo("net-COMMON_PRIVATE") {
				results.Add(
					"The nas instance has common private network",
					instance.NetworkID,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)

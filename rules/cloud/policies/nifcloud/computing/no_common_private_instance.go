package computing

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoCommonPrivateInstance = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0005",
		Aliases:     []string{"nifcloud-computing-no-common-private-instance"},
		Provider:    providers.NifcloudProvider,
		Service:     "computing",
		ShortCode:   "no-common-private-instance",
		Summary:     "The instance has common private network",
		Impact:      "The common private network is shared with other users",
		Resolution:  "Use private LAN",
		Explanation: `When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.`,
		Links: []string{
			"https://pfs.nifcloud.com/service/plan.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoCommonPrivateInstanceGoodExamples,
			BadExamples:         terraformNoCommonPrivateInstanceBadExamples,
			Links:               terraformNoCommonPrivateInstanceLinks,
			RemediationMarkdown: terraformNoCommonPrivateInstanceRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Nifcloud.Computing.Instances {
			for _, ni := range instance.NetworkInterfaces {
				if ni.NetworkID.EqualTo("net-COMMON_PRIVATE") {
					results.Add(
						"The instance has common private network",
						ni.NetworkID,
					)
				} else {
					results.AddPassed(&ni)
				}
			}
		}
		return
	},
)

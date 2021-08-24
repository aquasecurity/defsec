package compute

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/result"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckInstancesDoNotHavePublicIPs = rules.RuleDef{
	Provider:    provider.GoogleProvider,
	Service:     service,
	ShortCode:   "no-public-ip",
	Summary:     "Instances should not have public IP addresses",
	Impact:      "Direct exposure of an instance to the public internet",
	Resolution:  "Remove public IP",
	Explanation: `Instances should not be publicly exposed to the internet`,
	Severity:    severity.High,
	CheckFunc: func(s *state.State) []*result.Result {
		var results []*result.Result
		for _, instance := range s.Google.Compute.Instances {
			for _, networkInterface := range instance.NetworkInterfaces {
				if networkInterface.HasPublicIP.Value {
					results = append(results, result.New(
						networkInterface.HasPublicIP.Range,
						"Instance '%s' has a public IP allocated.",
						networkInterface.HasPublicIP.Reference),
					)
				}
			}
		}
		return results
	},
}

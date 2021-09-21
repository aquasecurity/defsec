package network

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckDisableRdpFromInternet = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "network",
		ShortCode:   "disable-rdp-from-internet",
		Summary:     "RDP access should not be accessible from the Internet, should be blocked on port 3389",
		Impact:      "Anyone from the internet can potentially RDP onto an instance",
		Resolution:  "Block RDP port from internet",
		Explanation: `RDP access can be configured on either the network security group or in the network security group rule.

RDP access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any). Consider using the Azure Bastion Service.`,
		Links: []string{ 
			"https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
					
				)
			}
		}
		return
	},
)

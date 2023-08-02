package network

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckAddSecurityGroupToVpnGateway = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0018",
		Aliases:     []string{"nifcloud-computing-add-security-group-to-vpn-gateway"},
		Provider:    providers.NifcloudProvider,
		Service:     "network",
		ShortCode:   "add-security-group-to-vpn-gateway",
		Summary:     "Missing security group for vpnGateway.",
		Impact:      "A security group controls the traffic that is allowed to reach and leave the resources that it is associated with.",
		Resolution:  "Add security group for all vpnGateways",
		Explanation: "Need to add a security group to your vpnGateway.",
		Links: []string{
			"https://pfs.nifcloud.com/help/vpngw/change.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddSecurityGroupToVpnGatewayGoodExamples,
			BadExamples:         terraformAddSecurityGroupToVpnGatewayBadExamples,
			Links:               terraformAddSecurityGroupToVpnGatewayLinks,
			RemediationMarkdown: terraformAddSecurityGroupToVpnGatewayRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, vpnGateway := range s.Nifcloud.Network.VpnGateways {
			if vpnGateway.Metadata.IsUnmanaged() {
				continue
			}
			if vpnGateway.SecurityGroup.IsEmpty() {
				results.Add(
					"VpnGateway does not have a securiy group.",
					vpnGateway.SecurityGroup,
				)
			} else {
				results.AddPassed(&vpnGateway)
			}
		}
		return
	},
)

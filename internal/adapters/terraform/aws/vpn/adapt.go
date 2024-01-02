package vpn

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/vpn"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type adapter struct {
	modules terraform.Modules
	vpnMap  map[string]*vpn.VPN
}

func (a *adapter) adaptVPNs() []vpn.VPN {
	for _, block := range a.modules.GetResourcesByType("aws_ec2_client_vpn_endpoint") {
		vpn := &vpn.VPN{
			BannerOptions: block.GetAttribute("client_login_banner_options").AsStringValueOrDefault("", block),
		}

		a.vpnMap[block.ID()] = vpn
	}

	var vpns []vpn.VPN
	for _, vpn := range a.vpnMap {
		vpns = append(vpns, *vpn)
	}

	return vpns
}

func getBannerOptions (b *terraform.Block, a *adapter) defsecTypes.StringValue {
	var options defsecTypes.StringValue
	for _, r := range a.modules.GetReferencingResources(b, "aws_ec2_client_vpn_endpoint", "client_login_banner_options") {
		options = r.GetAttribute("client_login_banner_options").AsStringValueOrDefault("", r)
	}
	return options
}
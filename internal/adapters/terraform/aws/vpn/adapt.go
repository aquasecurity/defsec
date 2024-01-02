package vpn

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/vpn"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) vpn.ClientVpn {
	return vpn.ClientVpn{
		Vpns: adaptVPNs(modules),
	}
}

func adaptVPNs(modules terraform.Modules) []vpn.VpnEndpoint {
	var vpnEndpoints []vpn.VpnEndpoint
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ec2_client_vpn_endpoint") {
			vpnEndpoints = append(vpnEndpoints, adaptVpn(resource))
		}
	}
	return vpnEndpoints
}

func adaptVpn(resource *terraform.Block) vpn.VpnEndpoint {
	vpnEndpoint := vpn.VpnEndpoint{
		Metadata:      resource.GetMetadata(),
		BannerOptions: defsecTypes.StringDefault("", resource.GetMetadata()),
	}

	bannerOptions := resource.GetAttribute("client_login_banner_options")
	vpnEndpoint.BannerOptions = bannerOptions.AsStringValueOrDefault("", resource)

	return vpnEndpoint
}

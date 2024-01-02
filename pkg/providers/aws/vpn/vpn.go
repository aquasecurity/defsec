package vpn

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ClientVpn struct {
	Vpns []VpnEndpoint
}

type VpnEndpoint struct {
	Metadata      defsecTypes.Metadata
	BannerOptions defsecTypes.StringValue
}

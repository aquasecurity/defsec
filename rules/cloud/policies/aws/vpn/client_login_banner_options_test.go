package vpn

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/vpn"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckClientLoginBannerOptions(t *testing.T) {
	tests := []struct {
		name     string
		input    vpn.ClientVpn
		expected bool
	}{
		{
			name: "VPN client missing login banner",
			input: vpn.ClientVpn{
				Vpns: []vpn.VpnEndpoint{
					{
						Metadata:      defsecTypes.NewTestMetadata(),
						BannerOptions: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "VPN client displays login banner",
			input: vpn.ClientVpn{
				Vpns: []vpn.VpnEndpoint{
					{
						Metadata:      defsecTypes.NewTestMetadata(),
						BannerOptions: defsecTypes.String("banner-message", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.VPN = test.input
			results := CheckClientLoginBannerOptions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckClientLoginBannerOptions.Rule().LongID() {
					found = true
				}
				if test.expected {
					assert.True(t, found, "Rule should have been found")
				} else {
					assert.False(t, found, "Rule should not have been found")
				}
			}
		})
	}
}

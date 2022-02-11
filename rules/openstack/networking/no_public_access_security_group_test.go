package networking

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/openstack"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccessSecurityGroup(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Networking
		expected bool
	}{
		{
			name: "SecrityGroup rule with public ingress addresse",
			input: openstack.Networking{
				Metadata:       types.NewTestMetadata(),
				Direction:      types.String("ingress", types.NewTestMetadata()),
				Ethertype:      types.String("IPv4", types.NewTestMetadata()),
				Protocol:       types.String("tcp", types.NewTestMetadata()),
				PortRangeMin:   types.Int(22, types.NewTestMetadata()),
				PortRangeMax:   types.Int(22, types.NewTestMetadata()),
				RemoteIPPrefix: types.String("0.0.0.0/0", types.NewTestMetadata()),
			},
			expected: true,
		},
		{
			name: "SecrityGroup rule with private ingress addresse",
			input: openstack.Networking{
				Metadata:       types.NewTestMetadata(),
				Direction:      types.String("ingress", types.NewTestMetadata()),
				Ethertype:      types.String("IPv4", types.NewTestMetadata()),
				Protocol:       types.String("tcp", types.NewTestMetadata()),
				PortRangeMin:   types.Int(22, types.NewTestMetadata()),
				PortRangeMax:   types.Int(22, types.NewTestMetadata()),
				RemoteIPPrefix: types.String("10.0.1.1/24", types.NewTestMetadata()),
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.OpenStack.Networking = test.input
			results := CheckNoPublicAccessSecurityGroup.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPublicAccessSecurityGroup.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}

package elb

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckAlbNotPublic(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer publicly accessible",
			input: elb.ELB{
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						Type:     types.String(elb.TypeApplication, types.NewTestMetadata()),
						Internal: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer internally accessible",
			input: elb.ELB{
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						Type:     types.String(elb.TypeApplication, types.NewTestMetadata()),
						Internal: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.ELB = test.input
			results := CheckAlbNotPublic.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckAlbNotPublic.Rule().LongID() {
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

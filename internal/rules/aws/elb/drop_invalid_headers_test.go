package elb

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDropInvalidHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer drop invalid headers disabled",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                types.NewTestMetadata(),
						Type:                    types.String(elb.TypeApplication, types.NewTestMetadata()),
						DropInvalidHeaderFields: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer drop invalid headers enabled",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                types.NewTestMetadata(),
						Type:                    types.String(elb.TypeApplication, types.NewTestMetadata()),
						DropInvalidHeaderFields: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		}, {
			name: "Classic load balanace doesn't fail when no drop headers",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						Type:     types.String(elb.TypeClassic, types.NewTestMetadata()),
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
			results := CheckDropInvalidHeaders.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDropInvalidHeaders.Rule().LongID() {
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

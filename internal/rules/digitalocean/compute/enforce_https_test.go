package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/digitalocean/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Load balancer forwarding rule using HTTP",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      types.NewTestMetadata(),
								EntryProtocol: types.String("http", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer forwarding rule using HTTPS",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      types.NewTestMetadata(),
								EntryProtocol: types.String("https", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.DigitalOcean.Compute = test.input
			results := CheckEnforceHttps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceHttps.Rule().LongID() {
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

package elb

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckHttpNotUsed(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer listener with HTTP protocol",
			input: elb.ELB{
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						Type:     types.String(elb.TypeApplication, types.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: types.NewTestMetadata(),
								Protocol: types.String("HTTP", types.NewTestMetadata()),
								DefaultAction: elb.Action{
									Metadata: types.NewTestMetadata(),
									Type:     types.String("forward", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener with HTTP protocol but redirect default action",
			input: elb.ELB{
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						Type:     types.String(elb.TypeApplication, types.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: types.NewTestMetadata(),
								Protocol: types.String("HTTP", types.NewTestMetadata()),
								DefaultAction: elb.Action{
									Metadata: types.NewTestMetadata(),
									Type:     types.String("redirect", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: elb.ELB{
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						Type:     types.String(elb.TypeApplication, types.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: types.NewTestMetadata(),
								Protocol: types.String("HTTPS", types.NewTestMetadata()),
								DefaultAction: elb.Action{
									Metadata: types.NewTestMetadata(),
									Type:     types.String("forward", types.NewTestMetadata()),
								},
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
			testState.AWS.ELB = test.input
			results := CheckHttpNotUsed.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckHttpNotUsed.Rule().LongID() {
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

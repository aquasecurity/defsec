package elb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String(elb.TypeApplication, defsecTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTP", defsecTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("forward", defsecTypes.NewTestMetadata()),
									},
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
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String(elb.TypeApplication, defsecTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTP", defsecTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("redirect", defsecTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol but redirect among multiple default actions",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String(elb.TypeApplication, defsecTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTP", defsecTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("forward", defsecTypes.NewTestMetadata()),
									},
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("redirect", defsecTypes.NewTestMetadata()),
									},
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
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String(elb.TypeApplication, defsecTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTPS", defsecTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Type:     defsecTypes.String("forward", defsecTypes.NewTestMetadata()),
									},
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckHttpNotUsed.Rule().LongID() {
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

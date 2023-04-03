package elb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer listener using TLS v1.0",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								TLSPolicy: defsecTypes.String("ELBSecurityPolicy-TLS-1-0-2015-04", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								TLSPolicy: defsecTypes.String("ELBSecurityPolicy-TLS-1-2-2017-01", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener using TLS v1.3",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								TLSPolicy: defsecTypes.String("ELBSecurityPolicy-TLS13-1-2-2021-06", defsecTypes.NewTestMetadata()),
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
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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

package elb

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/elb"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
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
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  types.NewTestMetadata(),
								TLSPolicy: types.String("ELBSecurityPolicy-TLS-1-0-2015-04", types.NewTestMetadata()),
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
				Metadata: types.NewTestMetadata(),
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: types.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  types.NewTestMetadata(),
								TLSPolicy: types.String("ELBSecurityPolicy-TLS-1-2-2017-01", types.NewTestMetadata()),
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
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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

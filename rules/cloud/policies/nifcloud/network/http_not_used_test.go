package network

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/network"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckHttpNotUsed(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Elastic Load balancer listener with HTTP protocol on global",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     defsecTypes.NewTestMetadata(),
							NetworkID:    defsecTypes.String("net-COMMON_GLOBAL", defsecTypes.NewTestMetadata()),
							IsVipNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTP", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Elastic Load balancer listener with HTTP protocol on internal",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     defsecTypes.NewTestMetadata(),
							NetworkID:    defsecTypes.String("some-network", defsecTypes.NewTestMetadata()),
							IsVipNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTP", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Elastic Load balancer listener with HTTPS protocol on global",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     defsecTypes.NewTestMetadata(),
							NetworkID:    defsecTypes.String("net-COMMON_GLOBAL", defsecTypes.NewTestMetadata()),
							IsVipNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTPS", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTP", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Protocol: defsecTypes.String("HTTPS", defsecTypes.NewTestMetadata()),
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
			testState.Nifcloud.Network = test.input
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

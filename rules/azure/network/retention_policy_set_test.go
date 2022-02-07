package network

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/network"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckRetentionPolicySet(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Network watcher flow log retention policy disabled",
			input: network.Network{
				Metadata: types.NewTestMetadata(),
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: types.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
							Days:     types.Int(100, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Network watcher flow log retention policy enabled for 30 days",
			input: network.Network{
				Metadata: types.NewTestMetadata(),
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: types.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							Days:     types.Int(30, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Network watcher flow log retention policy enabled for 100 days",
			input: network.Network{
				Metadata: types.NewTestMetadata(),
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: types.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							Days:     types.Int(100, types.NewTestMetadata()),
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
			testState.Azure.Network = test.input
			results := CheckRetentionPolicySet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckRetentionPolicySet.Rule().LongID() {
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

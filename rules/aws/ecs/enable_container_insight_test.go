package ecs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableContainerInsight(t *testing.T) {
	tests := []struct {
		name     string
		input    ecs.ECS
		expected bool
	}{
		{
			name: "Cluster with disabled container insights",
			input: ecs.ECS{
				Metadata: types.NewTestMetadata(),
				Clusters: []ecs.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 types.NewTestMetadata(),
							ContainerInsightsEnabled: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with enabled container insights",
			input: ecs.ECS{
				Metadata: types.NewTestMetadata(),
				Clusters: []ecs.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 types.NewTestMetadata(),
							ContainerInsightsEnabled: types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.ECS = test.input
			results := CheckEnableContainerInsight.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableContainerInsight.Rule().LongID() {
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

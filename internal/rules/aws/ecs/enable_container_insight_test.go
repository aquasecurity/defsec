package ecs

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableContainerInsight.Rule().LongID() {
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

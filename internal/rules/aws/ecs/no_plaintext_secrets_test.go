package ecs

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPlaintextSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    ecs.ECS
		expected bool
	}{
		{
			name: "Task definition with plaintext sensitive information",
			input: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: types.NewTestMetadata(),
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Metadata:  types.NewTestMetadata(),
								Name:      types.String("my_service", types.NewTestMetadata()),
								Image:     types.String("my_image", types.NewTestMetadata()),
								CPU:       types.Int(2, types.NewTestMetadata()),
								Memory:    types.Int(256, types.NewTestMetadata()),
								Essential: types.Bool(true, types.NewTestMetadata()),
								Environment: []ecs.EnvVar{
									{
										Name:  "ENVIRONMENT",
										Value: "development",
									},
									{
										Name:  "DATABASE_PASSWORD",
										Value: "password123",
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
			name: "Task definition without sensitive information",
			input: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: types.NewTestMetadata(),
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Metadata:  types.NewTestMetadata(),
								Name:      types.String("my_service", types.NewTestMetadata()),
								Image:     types.String("my_image", types.NewTestMetadata()),
								CPU:       types.Int(2, types.NewTestMetadata()),
								Memory:    types.Int(256, types.NewTestMetadata()),
								Essential: types.Bool(true, types.NewTestMetadata()),
								Environment: []ecs.EnvVar{
									{
										Name:  "ENVIRONMENT",
										Value: "development",
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
			testState.AWS.ECS = test.input
			results := CheckNoPlaintextSecrets.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPlaintextSecrets.Rule().LongID() {
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

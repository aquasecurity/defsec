package ecs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ecs"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
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
				Metadata: types.NewTestMetadata(),
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: types.NewTestMetadata(),
						ContainerDefinitions: types.String(`[
							{
							  "name": "my_service",
							  "essential": true,
							  "memory": 256,
							  "environment": [
								{ "name": "ENVIRONMENT", "value": "development" },
								{ "name": "DATABASE_PASSWORD", "value": "oh no D:"}
							  ]
							}
						  ]`, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Task definition without sensitive information",
			input: ecs.ECS{
				Metadata: types.NewTestMetadata(),
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: types.NewTestMetadata(),
						ContainerDefinitions: types.String(` [
							{
							  "name": "my_service",
							  "essential": true,
							  "memory": 256,
							  "environment": [
								{ "name": "ENVIRONMENT", "value": "development" }
							  ]
							}
						  ]`, types.NewTestMetadata()),
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
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPlaintextSecrets.Rule().LongID() {
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

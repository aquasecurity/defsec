package ecs

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    ecs.ECS
		expected bool
	}{
		{
			name: "ECS task definition unencrypted volume",
			input: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: types.NewTestMetadata(),
						Volumes: []ecs.Volume{
							{
								Metadata: types.NewTestMetadata(),
								EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
									Metadata:                 types.NewTestMetadata(),
									TransitEncryptionEnabled: types.Bool(false, types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "ECS task definition encrypted volume",
			input: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: types.NewTestMetadata(),
						Volumes: []ecs.Volume{
							{
								Metadata: types.NewTestMetadata(),
								EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
									Metadata:                 types.NewTestMetadata(),
									TransitEncryptionEnabled: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnableInTransitEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableInTransitEncryption.Rule().LongID() {
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

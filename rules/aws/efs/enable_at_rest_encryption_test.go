package efs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    efs.EFS
		expected bool
	}{
		{
			name: "positive result",
			input: efs.EFS{
				Metadata: types.NewTestMetadata(),
				FileSystems: []efs.FileSystem{
					{
						Metadata:  types.NewTestMetadata(),
						Encrypted: types.Bool(false, types.NewTestMetadata()),
					}},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: efs.EFS{
				Metadata: types.NewTestMetadata(),
				FileSystems: []efs.FileSystem{
					{
						Metadata:  types.NewTestMetadata(),
						Encrypted: types.Bool(true, types.NewTestMetadata()),
					}},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EFS = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableAtRestEncryption.Rule().LongID() {
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

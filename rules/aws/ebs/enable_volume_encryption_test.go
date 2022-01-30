package ebs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableVolumeEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    ebs.EBS
		expected bool
	}{
		{
			name: "unencrypted EBS volume",
			input: ebs.EBS{
				Metadata: types.NewTestMetadata(),
				Volumes: []ebs.Volume{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: ebs.Encryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "encrypted EBS volume",
			input: ebs.EBS{
				Metadata: types.NewTestMetadata(),
				Volumes: []ebs.Volume{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: ebs.Encryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.EBS = test.input
			results := CheckEnableVolumeEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableVolumeEncryption.Rule().LongID() {
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

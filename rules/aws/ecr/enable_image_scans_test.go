package ecr

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/ecr"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableImageScans(t *testing.T) {
	tests := []struct {
		name     string
		input    ecr.ECR
		expected bool
	}{
		{
			name: "ECR repository with image scans disabled",
			input: ecr.ECR{
				Metadata: types.NewTestMetadata(),
				Repositories: []ecr.Repository{
					{
						Metadata: types.NewTestMetadata(),
						ImageScanning: ecr.ImageScanning{
							Metadata:   types.NewTestMetadata(),
							ScanOnPush: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "ECR repository with image scans enabled",
			input: ecr.ECR{
				Metadata: types.NewTestMetadata(),
				Repositories: []ecr.Repository{
					{
						Metadata: types.NewTestMetadata(),
						ImageScanning: ecr.ImageScanning{
							Metadata:   types.NewTestMetadata(),
							ScanOnPush: types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.ECR = test.input
			results := CheckEnableImageScans.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableImageScans.Rule().LongID() {
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

package nas

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/nas"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionToNASSecurityGroup(t *testing.T) {
	tests := []struct {
		name     string
		input    nas.NAS
		expected bool
	}{
		{
			name: "NIFCLOUD nas security group with no description provided",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    defsecTypes.NewTestMetadata(),
						Description: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD nas security group with default description",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    defsecTypes.NewTestMetadata(),
						Description: defsecTypes.String("Managed by Terraform", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD nas security group with proper description",
			input: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    defsecTypes.NewTestMetadata(),
						Description: defsecTypes.String("some proper description", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.NAS = test.input
			results := CheckAddDescriptionToNASSecurityGroup.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAddDescriptionToNASSecurityGroup.Rule().LongID() {
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

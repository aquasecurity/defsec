package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRootHardwareMFAEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "root user without mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types.NewTestMetadata(),
						Name:     types.String("root", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "root user with virtual MFA mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types.NewTestMetadata(),
						Name:     types.String("root", types.NewTestMetadata()),
						MFADevices: []iam.MFADevice{
							{
								Metadata:  types.NewTestMetadata(),
								IsVirtual: types.Bool(true, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "other user without mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types.NewTestMetadata(),
						Name:     types.String("other", types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with hardware mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: types.NewTestMetadata(),
						Name:     types.String("root", types.NewTestMetadata()),
						MFADevices: []iam.MFADevice{
							{
								Metadata:  types.NewTestMetadata(),
								IsVirtual: types.Bool(false, types.NewTestMetadata()),
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
			testState.AWS.IAM = test.input
			results := checkRootHardwareMFAEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkRootHardwareMFAEnabled.Rule().LongID() {
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

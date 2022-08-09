package workspaces

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/workspaces"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableDiskEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    workspaces.WorkSpaces
		expected bool
	}{
		{
			name: "AWS Workspace with unencrypted root volume",
			input: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: types2.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: types2.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types2.NewTestMetadata(),
								Enabled:  types2.Bool(false, types2.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: types2.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types2.NewTestMetadata(),
								Enabled:  types2.Bool(true, types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Workspace with unencrypted user volume",
			input: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: types2.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: types2.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types2.NewTestMetadata(),
								Enabled:  types2.Bool(true, types2.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: types2.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types2.NewTestMetadata(),
								Enabled:  types2.Bool(false, types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},

		{
			name: "AWS Workspace with encrypted user and root volumes",
			input: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: types2.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: types2.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types2.NewTestMetadata(),
								Enabled:  types2.Bool(true, types2.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: types2.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types2.NewTestMetadata(),
								Enabled:  types2.Bool(true, types2.NewTestMetadata()),
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
			testState.AWS.WorkSpaces = test.input
			results := CheckEnableDiskEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableDiskEncryption.Rule().LongID() {
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

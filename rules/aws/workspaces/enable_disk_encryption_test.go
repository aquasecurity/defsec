package workspaces

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/workspaces"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
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
				Metadata: types.NewTestMetadata(),
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: types.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: types.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(false, types.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: types.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(true, types.NewTestMetadata()),
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
				Metadata: types.NewTestMetadata(),
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: types.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: types.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(true, types.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: types.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(false, types.NewTestMetadata()),
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
				Metadata: types.NewTestMetadata(),
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: types.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: types.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(true, types.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: types.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(true, types.NewTestMetadata()),
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
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableDiskEncryption.Rule().LongID() {
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

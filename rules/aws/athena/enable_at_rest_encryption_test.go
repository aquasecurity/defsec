package athena

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    athena.Athena
		expected bool
	}{
		{
			name: "AWS Athena database unencrypted",
			input: athena.Athena{
				Metadata: types.NewTestMetadata(),
				Databases: []athena.Database{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: types.NewTestMetadata(),
							Type:     types.String(athena.EncryptionTypeNone, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Athena workgroup unencrypted",
			input: athena.Athena{
				Metadata: types.NewTestMetadata(),
				Workgroups: []athena.Workgroup{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: types.NewTestMetadata(),
							Type:     types.String(athena.EncryptionTypeNone, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Athena database and workgroup encrypted",
			input: athena.Athena{
				Metadata: types.NewTestMetadata(),
				Databases: []athena.Database{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: types.NewTestMetadata(),
							Type:     types.String(athena.EncryptionTypeSSEKMS, types.NewTestMetadata()),
						},
					},
				},
				Workgroups: []athena.Workgroup{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: types.NewTestMetadata(),
							Type:     types.String(athena.EncryptionTypeSSEKMS, types.NewTestMetadata()),
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
			testState.AWS.Athena = test.input
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

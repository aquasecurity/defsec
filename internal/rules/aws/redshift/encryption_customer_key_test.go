package redshift

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    redshift.Redshift
		expected bool
	}{
		{
			name: "Redshift Cluster with encryption disabled",
			input: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
							KMSKeyID: types.String("some-key", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Redshift Cluster missing KMS key",
			input: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyID: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Redshift Cluster encrypted with KMS key",
			input: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyID: types.String("some-key", types.NewTestMetadata()),
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
			testState.AWS.Redshift = test.input
			results := CheckEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptionCustomerKey.Rule().LongID() {
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

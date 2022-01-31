package documentdb

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    documentdb.DocumentDB
		expected bool
	}{
		{
			name: "DocDB Cluster encryption missing KMS key",
			input: documentdb.DocumentDB{
				Metadata: types.NewTestMetadata(),
				Clusters: []documentdb.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "DocDB Instance encryption missing KMS key",
			input: documentdb.DocumentDB{
				Metadata: types.NewTestMetadata(),
				Clusters: []documentdb.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("kms-key", types.NewTestMetadata()),
						Instances: []documentdb.Instance{
							{
								Metadata: types.NewTestMetadata(),
								KMSKeyID: types.String("", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DocDB Cluster and Instance encrypted with proper KMS keys",
			input: documentdb.DocumentDB{
				Metadata: types.NewTestMetadata(),
				Clusters: []documentdb.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("kms-key", types.NewTestMetadata()),
						Instances: []documentdb.Instance{
							{
								Metadata: types.NewTestMetadata(),
								KMSKeyID: types.String("kms-key", types.NewTestMetadata()),
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
			testState.AWS.DocumentDB = test.input
			results := CheckEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEncryptionCustomerKey.Rule().LongID() {
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

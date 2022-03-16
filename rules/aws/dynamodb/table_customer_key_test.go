package dynamodb

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckTableCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    dynamodb.DynamoDB
		expected bool
	}{
		{
			name: "Cluster encryption missing KMS key",
			input: dynamodb.DynamoDB{
				Metadata: types.NewTestMetadata(),
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: types.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: types.NewTestMetadata(),
							KMSKeyID: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster encryption using default KMS key",
			input: dynamodb.DynamoDB{
				Metadata: types.NewTestMetadata(),
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: types.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: types.NewTestMetadata(),
							KMSKeyID: types.String(dynamodb.DefaultKMSKeyID, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster encryption using proper KMS key",
			input: dynamodb.DynamoDB{
				Metadata: types.NewTestMetadata(),
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: types.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: types.NewTestMetadata(),
							KMSKeyID: types.String("some-ok-key", types.NewTestMetadata()),
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
			testState.AWS.DynamoDB = test.input
			results := CheckTableCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckTableCustomerKey.Rule().LongID() {
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

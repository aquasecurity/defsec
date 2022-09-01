package bigquery

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/bigquery"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDatasetEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    bigquery.BigQuery
		expected bool
	}{
		{
			name: "Dataset missing KMS key name.",
			input: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						DefaultEncryptionConfiguration: bigquery.EncryptionConfiguration{
							Metadata:   defsecTypes.NewTestMetadata(),
							KMSKeyName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Dataset with KMS key name provided.",
			input: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						DefaultEncryptionConfiguration: bigquery.EncryptionConfiguration{
							Metadata:   defsecTypes.NewTestMetadata(),
							KMSKeyName: defsecTypes.String("kms-key-name", defsecTypes.NewTestMetadata()),
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
			testState.Google.BigQuery = test.input
			results := CheckDatasetEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDatasetEncryptionCustomerKey.Rule().LongID() {
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

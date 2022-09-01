package bigquery

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/pkg/providers/google/bigquery"
)

func Test_adaptTables(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []bigquery.Table
	}{
		{
			name: "Basic complete example",
			terraform: `
			resource "google_bigquery_table" "default" {
			  dataset_id = "my-dataset-id"
			  table_id   = "bar"
			
			  encryption_configuration {
			    kms_key_name = "my-kms-key"
			  }
			}`,
			expected: []bigquery.Table{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					ID:       defsecTypes.String("my-dataset-id", defsecTypes.NewTestMetadata()),
					EncryptionConfiguration: bigquery.EncryptionConfiguration{
						KMSKeyName: defsecTypes.String("my-kms-key", defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "Missing encryption_configuration block",
			terraform: `
			resource "google_bigquery_table" "default" {
			  dataset_id = "my-dataset-id"
			  table_id   = "bar"
			}`,
			expected: []bigquery.Table{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					ID:       defsecTypes.String("my-dataset-id", defsecTypes.NewTestMetadata()),
					EncryptionConfiguration: bigquery.EncryptionConfiguration{
						KMSKeyName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTables(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

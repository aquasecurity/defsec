package bigquery

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/pkg/providers/google/bigquery"
)

func Test_adaptDatasets(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []bigquery.Dataset
	}{
		{
			name: "basic",
			terraform: `
			resource "google_bigquery_dataset" "my_dataset" {
			  access {
			    role          = "OWNER"
			    special_group = "allAuthenticatedUsers"
			  }

			  access {
			    role   = "READER"
				domain = "hashicorp.com"
			  }

			  default_encryption_configuration {
			    kms_key_name = "my-kms-key"
			  }
			}`,
			expected: []bigquery.Dataset{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					ID:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
					AccessGrants: []bigquery.AccessGrant{
						{
							Metadata:     defsecTypes.NewTestMetadata(),
							Role:         defsecTypes.String("OWNER", defsecTypes.NewTestMetadata()),
							Domain:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
							SpecialGroup: defsecTypes.String(bigquery.SpecialGroupAllAuthenticatedUsers, defsecTypes.NewTestMetadata()),
						},
						{
							Metadata:     defsecTypes.NewTestMetadata(),
							Role:         defsecTypes.String("READER", defsecTypes.NewTestMetadata()),
							Domain:       defsecTypes.String("hashicorp.com", defsecTypes.NewTestMetadata()),
							SpecialGroup: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
					DefaultEncryptionConfiguration: bigquery.EncryptionConfiguration{
						KMSKeyName: defsecTypes.String("my-kms-key", defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "no access blocks or encryption",
			terraform: `
			resource "google_bigquery_dataset" "my_dataset" {
			  dataset_id                  = "example_dataset"
			}`,
			expected: []bigquery.Dataset{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					ID:       defsecTypes.String("example_dataset", defsecTypes.NewTestMetadata()),
					DefaultEncryptionConfiguration: bigquery.EncryptionConfiguration{
						KMSKeyName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "access block without fields",
			terraform: `
					resource "google_bigquery_dataset" "my_dataset" {
						access {
						}
					  }
		`,
			expected: []bigquery.Dataset{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					ID:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
					AccessGrants: []bigquery.AccessGrant{
						{
							Metadata:     defsecTypes.NewTestMetadata(),
							Role:         defsecTypes.String("", defsecTypes.NewTestMetadata()),
							Domain:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
							SpecialGroup: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
					DefaultEncryptionConfiguration: bigquery.EncryptionConfiguration{
						KMSKeyName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDatasets(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

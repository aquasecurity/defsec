package bigquery

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLines(t *testing.T) {
	src := `
resource "google_bigquery_dataset" "my_dataset" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  description                 = "This is a test description"
  location                    = "EU"
  default_table_expiration_ms = 3600000
	
  labels = {
    env = "default"
  }
	
  access {
    role          = "OWNER"
    special_group = "allAuthenticatedUsers"
  }
  
  access {
    role   = "READER"
    domain = "hashicorp.com"
  }

  default_encryption_configuration {
    kms_key_name = "projects/my-pet-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key"
  }
}

resource "google_bigquery_table" "default" {
  dataset_id = "my-dataset-id"
  table_id   = "bar"
  
  encryption_configuration {
    kms_key_name = "projects/my-pet-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key"
  }
}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Datasets, 1)
	dataset := adapted.Datasets[0]
	require.Len(t, dataset.AccessGrants, 2)

	assert.Equal(t, 14, dataset.AccessGrants[0].Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, dataset.AccessGrants[0].Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, dataset.AccessGrants[0].SpecialGroup.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, dataset.AccessGrants[0].SpecialGroup.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, dataset.AccessGrants[1].Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, dataset.AccessGrants[1].Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, dataset.AccessGrants[1].Domain.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, dataset.AccessGrants[1].Domain.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, dataset.DefaultEncryptionConfiguration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, dataset.DefaultEncryptionConfiguration.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 24, dataset.DefaultEncryptionConfiguration.KMSKeyName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, dataset.DefaultEncryptionConfiguration.KMSKeyName.GetMetadata().Range().GetEndLine())

	require.Len(t, adapted.Tables, 1)
	table := adapted.Tables[0]

	assert.Equal(t, 32, table.EncryptionConfiguration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, table.EncryptionConfiguration.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 33, table.EncryptionConfiguration.KMSKeyName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 33, table.EncryptionConfiguration.KMSKeyName.GetMetadata().Range().GetEndLine())
}

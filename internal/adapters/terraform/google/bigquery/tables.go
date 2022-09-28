package bigquery

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/bigquery"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func adaptTables(modules terraform.Modules) (tables []bigquery.Table) {
	for _, tableBlock := range modules.GetResourcesByType("google_bigquery_table") {
		table := bigquery.Table{
			Metadata: tableBlock.GetMetadata(),
			ID:       defsecTypes.StringDefault("", tableBlock.GetMetadata()),
			EncryptionConfiguration: bigquery.EncryptionConfiguration{
				Metadata:   tableBlock.GetMetadata(),
				KMSKeyName: defsecTypes.StringDefault("", tableBlock.GetMetadata()),
			},
		}

		IDAttr := tableBlock.GetAttribute("dataset_id")
		table.ID = IDAttr.AsStringValueOrDefault("", tableBlock)

		if encBlock := tableBlock.GetBlock("encryption_configuration"); encBlock.IsNotNil() {
			table.EncryptionConfiguration.Metadata = encBlock.GetMetadata()
			kmsKeyName := encBlock.GetAttribute("kms_key_name")
			table.EncryptionConfiguration.KMSKeyName = kmsKeyName.AsStringValueOrDefault("", encBlock)
		}
		tables = append(tables, table)
	}
	return tables
}

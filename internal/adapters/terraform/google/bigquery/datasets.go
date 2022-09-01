package bigquery

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/bigquery"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func adaptDatasets(modules terraform.Modules) (datasets []bigquery.Dataset) {
	for _, datasetBlock := range modules.GetResourcesByType("google_bigquery_dataset") {
		dataset := bigquery.Dataset{
			Metadata:     datasetBlock.GetMetadata(),
			ID:           defsecTypes.StringDefault("", datasetBlock.GetMetadata()),
			AccessGrants: nil,
			DefaultEncryptionConfiguration: bigquery.EncryptionConfiguration{
				Metadata:   datasetBlock.GetMetadata(),
				KMSKeyName: defsecTypes.StringDefault("", datasetBlock.GetMetadata()),
			},
		}

		IDAttr := datasetBlock.GetAttribute("dataset_id")
		dataset.ID = IDAttr.AsStringValueOrDefault("", datasetBlock)

		for _, accessBlock := range datasetBlock.GetBlocks("access") {
			roleAttr := accessBlock.GetAttribute("role")
			domainAttr := accessBlock.GetAttribute("domain")
			specialGrAttr := accessBlock.GetAttribute("special_group")

			accessGrant := bigquery.AccessGrant{
				Metadata:     accessBlock.GetMetadata(),
				Role:         roleAttr.AsStringValueOrDefault("", accessBlock),
				Domain:       domainAttr.AsStringValueOrDefault("", accessBlock),
				SpecialGroup: specialGrAttr.AsStringValueOrDefault("", accessBlock),
			}

			dataset.AccessGrants = append(dataset.AccessGrants, accessGrant)
		}

		if encBlock := datasetBlock.GetBlock("default_encryption_configuration"); encBlock.IsNotNil() {
			dataset.DefaultEncryptionConfiguration.Metadata = encBlock.GetMetadata()
			kmsKeyName := encBlock.GetAttribute("kms_key_name")
			dataset.DefaultEncryptionConfiguration.KMSKeyName = kmsKeyName.AsStringValueOrDefault("", encBlock)
		}
		datasets = append(datasets, dataset)
	}
	return datasets
}

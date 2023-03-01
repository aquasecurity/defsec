package glue

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/glue"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getDataCatalogEncryptionSettings(ctx parser.FileContext) glue.DataCatalogEncryptionSetting {

	resources := ctx.GetResourcesByType("AWS::Glue::DataCatalogEncryptionSettings")
	var settings glue.DataCatalogEncryptionSetting
	for _, r := range resources {
		settings = glue.DataCatalogEncryptionSetting{
			Metadata: r.Metadata(),
			EncryptionAtRest: glue.EncryptionAtRest{
				CatalogEncryptionMode: r.GetStringProperty("DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode"),
				SseAwsKmsKeyId:        r.GetStringProperty("DataCatalogEncryptionSettings.EncryptionAtRest.SseAwsKmsKeyId"),
			},
		}
	}
	return settings
}

func getSecurityConfigurations(ctx parser.FileContext) []glue.SecurityConfiguration {

	resources := ctx.GetResourcesByType("AWS::Glue::SecurityConfiguration")

	var securityConfigurations []glue.SecurityConfiguration

	for _, r := range resources {

		var s3encryptions []glue.S3Encryption
		for _, e := range r.GetProperty("EncryptionConfiguration.S3Encryptions").AsList() {
			s3encryptions = append(s3encryptions, glue.S3Encryption{
				Metadata:         e.Metadata(),
				S3EncryptionMode: e.GetStringProperty("S3EncryptionMode"),
			})
		}
		securityConfigurations = append(securityConfigurations, glue.SecurityConfiguration{
			Metadata: r.Metadata(),
			EncryptionConfiguration: glue.EncryptionConfiguration{
				Metadata:                   r.Metadata(),
				CloudWatchEncryptionMode:   r.GetStringProperty("EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode"),
				JobBookmarksEncryptionMode: r.GetStringProperty("EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode"),
				S3Encryptions:              s3encryptions,
			},
		})
	}
	return securityConfigurations
}

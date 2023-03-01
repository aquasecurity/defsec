package glue

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Glue struct {
	SecurityConfigurations        []SecurityConfiguration
	DataCatalogEncryptionSettings DataCatalogEncryptionSetting
}

type SecurityConfiguration struct {
	Metadata                defsecTypes.Metadata
	EncryptionConfiguration EncryptionConfiguration
}

type EncryptionConfiguration struct {
	Metadata                   defsecTypes.Metadata
	CloudWatchEncryptionMode   defsecTypes.StringValue
	JobBookmarksEncryptionMode defsecTypes.StringValue
	S3Encryptions              []S3Encryption
}

type S3Encryption struct {
	Metadata         defsecTypes.Metadata
	S3EncryptionMode defsecTypes.StringValue
}

type DataCatalogEncryptionSetting struct {
	Metadata         defsecTypes.Metadata
	EncryptionAtRest EncryptionAtRest
}

type EncryptionAtRest struct {
	Metadata              defsecTypes.Metadata
	CatalogEncryptionMode defsecTypes.StringValue
	SseAwsKmsKeyId        defsecTypes.StringValue
}

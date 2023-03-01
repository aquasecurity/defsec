package iotsitewise

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type IoTSiteWise struct {
	DefaultEncryptionConfiguration DefaultEncryptionConfiguration
}

type DefaultEncryptionConfiguration struct {
	Metadata       defsecTypes.Metadata
	EncryptionType defsecTypes.StringValue
	KmsKeyArn      defsecTypes.StringValue
}

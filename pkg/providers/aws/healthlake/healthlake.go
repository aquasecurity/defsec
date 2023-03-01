package healthlake

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type HealthLake struct {
	FHIRDatastores []FHIRDatastore
}

type FHIRDatastore struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

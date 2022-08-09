package neptune

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	defsecTypes.Metadata
	Logging          Logging
	StorageEncrypted defsecTypes.BoolValue
	KMSKeyID         defsecTypes.StringValue
}

type Logging struct {
	defsecTypes.Metadata
	Audit defsecTypes.BoolValue
}

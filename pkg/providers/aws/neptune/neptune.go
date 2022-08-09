package neptune

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	types2.Metadata
	Logging          Logging
	StorageEncrypted types2.BoolValue
	KMSKeyID         types2.StringValue
}

type Logging struct {
	types2.Metadata
	Audit types2.BoolValue
}

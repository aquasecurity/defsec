package memorydb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type MemoryDB struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

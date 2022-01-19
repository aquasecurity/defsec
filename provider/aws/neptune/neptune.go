package neptune

import "github.com/aquasecurity/defsec/types"

type Neptune struct {
	types.Metadata
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	Logging          Logging
	StorageEncrypted types.BoolValue
	KMSKeyID         types.StringValue
}

type Logging struct {
	types.Metadata
	Audit types.BoolValue
}

func (c *Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Cluster) GetRawValue() interface{} {
	return nil
}

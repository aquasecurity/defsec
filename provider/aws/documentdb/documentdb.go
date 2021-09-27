package documentdb

import "github.com/aquasecurity/defsec/types"

type DocumentDB struct {
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	types.Metadata
	Identifier        types.StringValue
	EnabledLogExports []types.StringValue
	Instances         []Instance
	StorageEncrypted  types.BoolValue
	KMSKeyID          types.StringValue
}

func (c Cluster) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c Cluster) GetRawValue() interface{} {
	return nil
}

type Instance struct {
	types.Metadata
	KMSKeyID types.StringValue
}

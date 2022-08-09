package documentdb

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type DocumentDB struct {
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	types2.Metadata
	Identifier        types2.StringValue
	EnabledLogExports []types2.StringValue
	Instances         []Instance
	StorageEncrypted  types2.BoolValue
	KMSKeyID          types2.StringValue
}

type Instance struct {
	types2.Metadata
	KMSKeyID types2.StringValue
}

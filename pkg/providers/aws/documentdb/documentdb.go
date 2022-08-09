package documentdb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type DocumentDB struct {
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	defsecTypes.Metadata
	Identifier        defsecTypes.StringValue
	EnabledLogExports []defsecTypes.StringValue
	Instances         []Instance
	StorageEncrypted  defsecTypes.BoolValue
	KMSKeyID          defsecTypes.StringValue
}

type Instance struct {
	defsecTypes.Metadata
	KMSKeyID defsecTypes.StringValue
}

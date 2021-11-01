package neptune

import "github.com/aquasecurity/defsec/types"

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	Logging          Logging
	StorageEncrypted types.BoolValue
	KMSKeyID         types.StringValue
}

type Logging struct {
	Audit types.BoolValue
}

package dynamodb

import "github.com/aquasecurity/defsec/types"

type DynamoDB struct {
	DAXClusters []DAXCluster
}

type DAXCluster struct {
	*types.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  types.BoolValue
}

type ServerSideEncryption struct {
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

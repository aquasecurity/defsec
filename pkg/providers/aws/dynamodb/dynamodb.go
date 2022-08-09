package dynamodb

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type DynamoDB struct {
	DAXClusters []DAXCluster
	Tables      []Table
}

type DAXCluster struct {
	types2.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  types2.BoolValue
}

type Table struct {
	types2.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  types2.BoolValue
}

type ServerSideEncryption struct {
	types2.Metadata
	Enabled  types2.BoolValue
	KMSKeyID types2.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"

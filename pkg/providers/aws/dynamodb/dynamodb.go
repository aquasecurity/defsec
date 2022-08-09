package dynamodb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type DynamoDB struct {
	DAXClusters []DAXCluster
	Tables      []Table
}

type DAXCluster struct {
	defsecTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  defsecTypes.BoolValue
}

type Table struct {
	defsecTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  defsecTypes.BoolValue
}

type ServerSideEncryption struct {
	defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"

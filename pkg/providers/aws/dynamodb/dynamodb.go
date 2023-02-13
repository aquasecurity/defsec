package dynamodb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type DynamoDB struct {
	DAXClusters []DAXCluster
	Tables      []Table
	Backups     []Backup
}

type DAXCluster struct {
	Metadata             defsecTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  defsecTypes.BoolValue
}

type Backup struct {
	Metadata defsecTypes.Metadata
}

type Table struct {
	Metadata               defsecTypes.Metadata
	ServerSideEncryption   ServerSideEncryption
	PointInTimeRecovery    defsecTypes.BoolValue
	ContinuousBackupStatus defsecTypes.StringValue
}

type ServerSideEncryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"

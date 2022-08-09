package rds

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type RDS struct {
	Instances []Instance
	Clusters  []Cluster
	Classic   Classic
}

type Cluster struct {
	defsecTypes.Metadata
	BackupRetentionPeriodDays defsecTypes.IntValue
	ReplicationSourceARN      defsecTypes.StringValue
	PerformanceInsights       PerformanceInsights
	Instances                 []ClusterInstance
	Encryption                Encryption
	PublicAccess              defsecTypes.BoolValue
}

type Encryption struct {
	defsecTypes.Metadata
	EncryptStorage defsecTypes.BoolValue
	KMSKeyID       defsecTypes.StringValue
}

type Instance struct {
	defsecTypes.Metadata
	BackupRetentionPeriodDays defsecTypes.IntValue
	ReplicationSourceARN      defsecTypes.StringValue
	PerformanceInsights       PerformanceInsights
	Encryption                Encryption
	PublicAccess              defsecTypes.BoolValue
}

type ClusterInstance struct {
	defsecTypes.Metadata
	Instance
	ClusterIdentifier defsecTypes.StringValue
}

type PerformanceInsights struct {
	defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

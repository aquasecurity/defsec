package rds

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type RDS struct {
	Instances []Instance
	Clusters  []Cluster
	Classic   Classic
}

type Cluster struct {
	types2.Metadata
	BackupRetentionPeriodDays types2.IntValue
	ReplicationSourceARN      types2.StringValue
	PerformanceInsights       PerformanceInsights
	Instances                 []ClusterInstance
	Encryption                Encryption
	PublicAccess              types2.BoolValue
}

type Encryption struct {
	types2.Metadata
	EncryptStorage types2.BoolValue
	KMSKeyID       types2.StringValue
}

type Instance struct {
	types2.Metadata
	BackupRetentionPeriodDays types2.IntValue
	ReplicationSourceARN      types2.StringValue
	PerformanceInsights       PerformanceInsights
	Encryption                Encryption
	PublicAccess              types2.BoolValue
}

type ClusterInstance struct {
	types2.Metadata
	Instance
	ClusterIdentifier types2.StringValue
}

type PerformanceInsights struct {
	types2.Metadata
	Enabled  types2.BoolValue
	KMSKeyID types2.StringValue
}

package rds

import "github.com/aquasecurity/defsec/types"

type RDS struct {
	Instances []Instance
	Clusters  []Cluster
	Classic   Classic
}

type Cluster struct {
	types.Metadata
	BackupRetentionPeriodDays types.IntValue
	ReplicationSourceARN      types.StringValue
	PerformanceInsights       PerformanceInsights
	Instance                  []ClusterInstance
	Encryption                Encryption
}

type Encryption struct {
	EncryptStorage types.BoolValue
	KMSKeyID       types.StringValue
}

type Instance struct {
	BackupRetentionPeriodDays types.IntValue
	PerformanceInsights       PerformanceInsights
	Encryption                Encryption
	PublicAccess              types.BoolValue
}

type ClusterInstance Instance

type PerformanceInsights struct {
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

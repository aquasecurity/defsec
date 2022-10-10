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
	Metadata                  defsecTypes.Metadata
	BackupRetentionPeriodDays defsecTypes.IntValue
	ReplicationSourceARN      defsecTypes.StringValue
	PerformanceInsights       PerformanceInsights
	Instances                 []ClusterInstance
	Encryption                Encryption
	PublicAccess              defsecTypes.BoolValue
	Engine                    defsecTypes.StringValue
}

const (
	EngineAurora           = "aurora"
	EngineAuroraMysql      = "aurora-mysql"
	EngineAuroraPostgresql = "aurora-postgresql"
	EngineMySQL            = "mysql"
	EnginePostgres         = "postgres"
)

type Encryption struct {
	Metadata       defsecTypes.Metadata
	EncryptStorage defsecTypes.BoolValue
	KMSKeyID       defsecTypes.StringValue
}

type Instance struct {
	Metadata                  defsecTypes.Metadata
	BackupRetentionPeriodDays defsecTypes.IntValue
	ReplicationSourceARN      defsecTypes.StringValue
	PerformanceInsights       PerformanceInsights
	Encryption                Encryption
	PublicAccess              defsecTypes.BoolValue
	Engine                    defsecTypes.StringValue
	IAMAuthEnabled            defsecTypes.BoolValue
}

type ClusterInstance struct {
	Instance
	ClusterIdentifier defsecTypes.StringValue
}

type PerformanceInsights struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

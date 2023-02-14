package elasticache

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ElastiCache struct {
	Clusters           []Cluster
	ReplicationGroups  []ReplicationGroup
	SecurityGroups     []SecurityGroup
	ReservedCacheNodes []ReservedCacheNode
}

type Cluster struct {
	Metadata                 defsecTypes.Metadata
	Id                       defsecTypes.StringValue
	EngineVersion            defsecTypes.StringValue
	NumCacheNodes            defsecTypes.IntValue
	AtRestEncryptionEnabled  defsecTypes.BoolValue
	TransitEncryptionEnabled defsecTypes.BoolValue
	CacheSubnetGroupName     defsecTypes.StringValue
	ConfigurationEndpoint    ConfigurationEndpoint
	Engine                   defsecTypes.StringValue
	NodeType                 defsecTypes.StringValue
	SnapshotRetentionLimit   defsecTypes.IntValue // days
}

type ConfigurationEndpoint struct {
	Metadata defsecTypes.Metadata
	Port     defsecTypes.IntValue
}

type ReplicationGroup struct {
	Metadata                 defsecTypes.Metadata
	MultiAZ                  defsecTypes.BoolValue
	KmsKeyId                 defsecTypes.StringValue
	TransitEncryptionEnabled defsecTypes.BoolValue
	AtRestEncryptionEnabled  defsecTypes.BoolValue
}

type SecurityGroup struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
}

type ReservedCacheNode struct {
	Metadata  defsecTypes.Metadata
	StartTime defsecTypes.TimeValue
	Duration  defsecTypes.IntValue
	State     defsecTypes.StringValue
	NodeType  defsecTypes.StringValue
}

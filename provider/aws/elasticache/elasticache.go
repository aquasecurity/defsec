package elasticache

import "github.com/aquasecurity/defsec/types"

type ElastiCache struct {
	Clusters          []Cluster
	ReplicationGroups []ReplicationGroup
	SecurityGroups    []SecurityGroup
}

type Cluster struct {
	Engine                 types.StringValue
	NodeType               types.StringValue
	SnapshotRetentionLimit types.IntValue // days
}

type ReplicationGroup struct {
	TransitEncryptionEnabled types.BoolValue
}

type SecurityGroup struct {
	*types.Metadata
	Description types.StringValue
}

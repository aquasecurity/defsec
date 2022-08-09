package elasticache

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type ElastiCache struct {
	Clusters          []Cluster
	ReplicationGroups []ReplicationGroup
	SecurityGroups    []SecurityGroup
}

type Cluster struct {
	types2.Metadata
	Engine                 types2.StringValue
	NodeType               types2.StringValue
	SnapshotRetentionLimit types2.IntValue // days
}

type ReplicationGroup struct {
	types2.Metadata
	TransitEncryptionEnabled types2.BoolValue
	AtRestEncryptionEnabled  types2.BoolValue
}

type SecurityGroup struct {
	types2.Metadata
	Description types2.StringValue
}

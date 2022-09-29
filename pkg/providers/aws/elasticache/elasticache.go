package elasticache

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ElastiCache struct {
	Clusters          []Cluster
	ReplicationGroups []ReplicationGroup
	SecurityGroups    []SecurityGroup
}

type Cluster struct {
	Metadata               defsecTypes.Metadata
	Engine                 defsecTypes.StringValue
	NodeType               defsecTypes.StringValue
	SnapshotRetentionLimit defsecTypes.IntValue // days
}

type ReplicationGroup struct {
	Metadata                 defsecTypes.Metadata
	TransitEncryptionEnabled defsecTypes.BoolValue
	AtRestEncryptionEnabled  defsecTypes.BoolValue
}

type SecurityGroup struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
}

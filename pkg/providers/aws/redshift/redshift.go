package redshift

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Redshift struct {
	Clusters       []Cluster
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	defsecTypes.Metadata
	Description defsecTypes.StringValue
}

type Cluster struct {
	defsecTypes.Metadata
	Encryption      Encryption
	SubnetGroupName defsecTypes.StringValue
}

type Encryption struct {
	defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

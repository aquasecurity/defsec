package redshift

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Redshift struct {
	Clusters       []Cluster
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
}

type Cluster struct {
	Metadata        defsecTypes.Metadata
	Encryption      Encryption
	SubnetGroupName defsecTypes.StringValue
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

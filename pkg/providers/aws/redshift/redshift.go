package redshift

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Redshift struct {
	Clusters       []Cluster
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	types2.Metadata
	Description types2.StringValue
}

type Cluster struct {
	types2.Metadata
	Encryption      Encryption
	SubnetGroupName types2.StringValue
}

type Encryption struct {
	types2.Metadata
	Enabled  types2.BoolValue
	KMSKeyID types2.StringValue
}

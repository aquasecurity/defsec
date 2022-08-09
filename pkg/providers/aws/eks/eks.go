package eks

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type EKS struct {
	Clusters []Cluster
}

type Cluster struct {
	types2.Metadata
	Logging             Logging
	Encryption          Encryption
	PublicAccessEnabled types2.BoolValue
	PublicAccessCIDRs   []types2.StringValue
}

type Logging struct {
	types2.Metadata
	API               types2.BoolValue
	Audit             types2.BoolValue
	Authenticator     types2.BoolValue
	ControllerManager types2.BoolValue
	Scheduler         types2.BoolValue
}

type Encryption struct {
	types2.Metadata
	Secrets  types2.BoolValue
	KMSKeyID types2.StringValue
}

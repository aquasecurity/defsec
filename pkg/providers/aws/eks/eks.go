package eks

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type EKS struct {
	Clusters []Cluster
}

type Cluster struct {
	defsecTypes.Metadata
	Logging             Logging
	Encryption          Encryption
	PublicAccessEnabled defsecTypes.BoolValue
	PublicAccessCIDRs   []defsecTypes.StringValue
}

type Logging struct {
	defsecTypes.Metadata
	API               defsecTypes.BoolValue
	Audit             defsecTypes.BoolValue
	Authenticator     defsecTypes.BoolValue
	ControllerManager defsecTypes.BoolValue
	Scheduler         defsecTypes.BoolValue
}

type Encryption struct {
	defsecTypes.Metadata
	Secrets  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

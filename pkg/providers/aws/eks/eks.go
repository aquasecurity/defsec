package eks

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type EKS struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata             defsecTypes.Metadata
	Version              defsecTypes.StringValue
	PlatFormVersion      defsecTypes.StringValue
	Logging              Logging
	Encryption           Encryption
	PublicAccessEnabled  defsecTypes.BoolValue
	PrivateAccessEnabled defsecTypes.BoolValue
	PublicAccessCIDRs    []defsecTypes.StringValue
	SecurityGroupIDs     []defsecTypes.StringValue
}

type Logging struct {
	Metadata          defsecTypes.Metadata
	API               defsecTypes.BoolValue
	Audit             defsecTypes.BoolValue
	Authenticator     defsecTypes.BoolValue
	ControllerManager defsecTypes.BoolValue
	Scheduler         defsecTypes.BoolValue
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Secrets  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

package synapse

import "github.com/aquasecurity/defsec/types"

type Synapse struct {
	types.Metadata
	Workspaces []Workspace
}

type Workspace struct {
	types.Metadata
	EnableManagedVirtualNetwork types.BoolValue
}

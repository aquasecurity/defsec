package synapse

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Synapse struct {
	Workspaces []Workspace
}

type Workspace struct {
	types2.Metadata
	EnableManagedVirtualNetwork types2.BoolValue
}

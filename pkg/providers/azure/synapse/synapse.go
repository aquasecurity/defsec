package synapse

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Synapse struct {
	Workspaces []Workspace
}

type Workspace struct {
	defsecTypes.Metadata
	EnableManagedVirtualNetwork defsecTypes.BoolValue
}

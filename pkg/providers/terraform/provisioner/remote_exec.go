package provisioner

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type RemoteExec struct {
	Metadata   defsecTypes.Metadata
	Connection Connection
	Inline     []defsecTypes.StringValue
	Script     defsecTypes.StringValue
	Scripts    []defsecTypes.StringValue
}

package provisioner

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type LocalExec struct {
	Metadata    defsecTypes.Metadata
	Command     defsecTypes.StringValue
	WorkingDir  defsecTypes.StringValue
	Interpreter []defsecTypes.StringValue
	Environment defsecTypes.MapValue
}

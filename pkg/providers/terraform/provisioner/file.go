package provisioner

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type File struct {
	Metadata    defsecTypes.Metadata
	Connection  Connection
	Source      defsecTypes.StringValue
	Content     defsecTypes.StringValue
	Destination defsecTypes.StringValue
}

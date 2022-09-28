package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ProjectMetadata struct {
	Metadata      defsecTypes.Metadata
	EnableOSLogin defsecTypes.BoolValue
}

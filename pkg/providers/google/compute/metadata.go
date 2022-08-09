package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ProjectMetadata struct {
	defsecTypes.Metadata
	EnableOSLogin defsecTypes.BoolValue
}

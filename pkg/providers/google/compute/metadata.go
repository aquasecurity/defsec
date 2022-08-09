package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type ProjectMetadata struct {
	types2.Metadata
	EnableOSLogin types2.BoolValue
}

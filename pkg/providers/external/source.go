package external

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Source struct {
	Metadata   defsecTypes.Metadata
	Program    []defsecTypes.StringValue
	WorkingDir defsecTypes.StringValue
	Query      defsecTypes.MapValue
}

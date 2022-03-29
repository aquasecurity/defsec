package datafactory

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type DataFactory struct {
	types.Metadata
	DataFactories []Factory
}

type Factory struct {
	types.Metadata
	EnablePublicNetwork types.BoolValue
}

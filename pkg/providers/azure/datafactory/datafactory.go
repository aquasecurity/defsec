package datafactory

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	types2.Metadata
	EnablePublicNetwork types2.BoolValue
}

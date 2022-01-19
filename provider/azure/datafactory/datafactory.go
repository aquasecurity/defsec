package datafactory

import "github.com/aquasecurity/defsec/types"

type DataFactory struct {
	types.Metadata
	DataFactories []Factory
}

type Factory struct {
	types.Metadata
	EnablePublicNetwork types.BoolValue
}

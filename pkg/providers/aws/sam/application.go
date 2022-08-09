package sam

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Application struct {
	types2.Metadata
	LocationPath types2.StringValue
	Location     Location
}

type Location struct {
	types2.Metadata
	ApplicationID   types2.StringValue
	SemanticVersion types2.StringValue
}

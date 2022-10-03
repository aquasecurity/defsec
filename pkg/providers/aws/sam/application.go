package sam

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Application struct {
	Metadata     defsecTypes.Metadata
	LocationPath defsecTypes.StringValue
	Location     Location
}

type Location struct {
	Metadata        defsecTypes.Metadata
	ApplicationID   defsecTypes.StringValue
	SemanticVersion defsecTypes.StringValue
}

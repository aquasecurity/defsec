package compute

import "github.com/aquasecurity/defsec/definition"

type ProjectMetadata struct {
	*definition.Metadata
	Values map[string]definition.StringValue
}

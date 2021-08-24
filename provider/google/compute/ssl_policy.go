package compute

import "github.com/aquasecurity/defsec/definition"

type SSLPolicy struct {
	*definition.Metadata
	Name              definition.StringValue
	Profile           definition.StringValue
	MinimumTLSVersion definition.StringValue
}

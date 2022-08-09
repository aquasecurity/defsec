package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type SSLPolicy struct {
	types2.Metadata
	Name              types2.StringValue
	Profile           types2.StringValue
	MinimumTLSVersion types2.StringValue
}

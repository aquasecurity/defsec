package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SSLPolicy struct {
	defsecTypes.Metadata
	Name              defsecTypes.StringValue
	Profile           defsecTypes.StringValue
	MinimumTLSVersion defsecTypes.StringValue
}

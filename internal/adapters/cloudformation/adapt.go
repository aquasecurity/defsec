package cloudformation

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloudformation/aws"
	"github.com/aquasecurity/defsec/internal/state"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}

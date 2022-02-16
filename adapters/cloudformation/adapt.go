package adapter

import (
	"github.com/aquasecurity/defsec/adapters/cloudformation/aws"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}

package adapter

import (
	"github.com/aquasecurity/defsec/adapters/cloudformation/aws"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	defer func() {
		if r := recover(); r != nil {
			// meta := cfFile.Metadata()
			// debug.Log("An error occurred while adapting %s: \n\n\t%r", meta.Range().GetFilename(), r)
		}
	}()

	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}

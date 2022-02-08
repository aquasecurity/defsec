package adapter

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/state"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	defer func() {
		if r := recover(); r != nil {
			meta := cfFile.Metadata()
			debug.Log("An error occurred while adapting %s: \n\n\t%r", meta.Range().GetFilename(), r)
		}
	}()

	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}

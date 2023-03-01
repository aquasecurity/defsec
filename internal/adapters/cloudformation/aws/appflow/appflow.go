package appflow

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/appflow"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) appflow.Appflow {
	return appflow.Appflow{
		ListFlows: getListflow(cfFile),
	}
}

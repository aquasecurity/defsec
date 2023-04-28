package apprunner

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/apprunner"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) apprunner.Apprunner {
	return apprunner.Apprunner{
		ListServices: getListService(cfFile),
	}
}

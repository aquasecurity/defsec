package mwaa

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/mwaa"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) mwaa.Mwaa {
	return mwaa.Mwaa{
		Environments: getEnvironments(cfFile),
	}
}

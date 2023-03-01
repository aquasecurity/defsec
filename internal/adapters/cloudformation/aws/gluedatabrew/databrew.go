package gluedatabrew

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/gluedatabrew"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) gluedatabrew.GlueDataBrew {
	return gluedatabrew.GlueDataBrew{
		Jobs: getJobs(cfFile),
	}
}

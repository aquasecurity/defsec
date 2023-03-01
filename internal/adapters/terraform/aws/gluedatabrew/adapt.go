package gluedatabrew

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/gluedatabrew"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) gluedatabrew.GlueDataBrew {
	return gluedatabrew.GlueDataBrew{
		Jobs: nil,
	}
}

package connect

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/connect"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) connect.Connect {
	return connect.Connect{
		Instances: getInstances(cfFile),
	}
}

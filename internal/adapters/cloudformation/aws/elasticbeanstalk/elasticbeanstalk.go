package elasticbeanstalk

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticbeanstalk"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) elasticbeanstalk.ElasticBeanStalk {
	return elasticbeanstalk.ElasticBeanStalk{
		Environments: getEnvironments(cfFile),
	}
}

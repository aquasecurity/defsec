package elasticbeanstalk

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticbeanstalk"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getEnvironments(ctx parser.FileContext) []elasticbeanstalk.Environment {

	resources := ctx.GetResourcesByType("AWS::ElasticBeanstalk::Environment")

	var EBs []elasticbeanstalk.Environment

	for _, r := range resources {
		EBs = append(EBs, elasticbeanstalk.Environment{
			Metadata:       r.Metadata(),
			HealthStatus:   types.String("", r.Metadata()),
			OptionSettings: getOptionSettings(r),
		})
	}
	return EBs
}

func getOptionSettings(resource *parser.Resource) []elasticbeanstalk.OptionSetting {

	var OS []elasticbeanstalk.OptionSetting

	for _, r := range resource.GetProperty("OptionSettings").AsList() {
		OS = append(OS, elasticbeanstalk.OptionSetting{
			Metadata:   r.Metadata(),
			NameSpace:  r.GetStringProperty("NameSpace"),
			OptionName: r.GetStringProperty("OptionName"),
			Value:      r.GetStringProperty("Value"),
		})
	}
	return OS
}

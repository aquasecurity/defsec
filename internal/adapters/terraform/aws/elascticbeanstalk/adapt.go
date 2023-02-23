package elascticbeanstalk

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticbeanstalk"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) elasticbeanstalk.ElasticBeanStalk {
	return elasticbeanstalk.ElasticBeanStalk{
		Environments: adaptEnvironments(modules),
	}
}

func adaptEnvironments(modules terraform.Modules) []elasticbeanstalk.Environment {
	var enviroments []elasticbeanstalk.Environment
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elastic_beanstalk_environment") {
			enviroments = append(enviroments, adaptEnvironment(resource))
		}
	}
	return enviroments
}

func adaptEnvironment(resource *terraform.Block) elasticbeanstalk.Environment {

	var optionsettings []elasticbeanstalk.OptionSetting
	for _, os := range resource.GetBlocks("setting") {
		optionsettings = append(optionsettings, elasticbeanstalk.OptionSetting{
			Metadata:   os.GetMetadata(),
			NameSpace:  os.GetAttribute("namespace").AsStringValueOrDefault("", os),
			OptionName: os.GetAttribute("name").AsStringValueOrDefault("", os),
			Value:      os.GetAttribute("value").AsStringValueOrDefault("", os),
		})
	}

	return elasticbeanstalk.Environment{
		Metadata:       resource.GetMetadata(),
		HealthStatus:   types.String("", resource.GetMetadata()),
		OptionSettings: optionsettings,
	}
}

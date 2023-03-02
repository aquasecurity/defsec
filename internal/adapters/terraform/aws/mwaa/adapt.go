package mwaa

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/mwaa"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) mwaa.Mwaa {
	return mwaa.Mwaa{
		Environments: adaptEnvironments(modules),
	}
}

func adaptEnvironments(modules terraform.Modules) []mwaa.Environmnet {
	var environments []mwaa.Environmnet
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_mwaa_environment") {
			environments = append(environments, mwaa.Environmnet{
				Metadata:            resource.GetMetadata(),
				ExecutionRoleArn:    resource.GetAttribute("execution_role_arn").AsStringValueOrDefault("", resource),
				KmsKey:              resource.GetAttribute("kms_key").AsStringValueOrDefault("", resource),
				WebserverAccessMode: resource.GetAttribute("webserver_access_mode").AsStringValueOrDefault("PRIVATE_ONLY", resource),
			})
		}
	}
	return environments
}

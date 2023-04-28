package apprunner

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/apprunner"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) apprunner.Apprunner {
	return apprunner.Apprunner{
		ListServices: getServiceArn(modules),
	}
}

func getServiceArn(modules terraform.Modules) []apprunner.ListService {
	var serviceArn []apprunner.ListService
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_apprunner_service") {
			serviceArn = append(serviceArn, adaptServiceArn(resource, modules))
		}
	}

	return serviceArn
}

func adaptServiceArn(resource *terraform.Block, modules terraform.Modules) apprunner.ListService {
	var keyId types.StringValue
	keyIdBlock := resource.GetBlock("encryption_configuration")
	if keyIdBlock.IsNotNil() {
		keyId = keyIdBlock.GetAttribute("kms_key").AsStringValueOrDefault("", keyIdBlock)
	}

	return apprunner.ListService{
		Metadata:   resource.GetMetadata(),
		ServiceArn: resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
		KmsKey:     keyId,
	}
}

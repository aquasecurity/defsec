package apprunner

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/apprunner"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) apprunner.Apprunner {
	return apprunner.Apprunner{
		DescribeServices: getKmsKey(modules),
		ListServices:     getServiceArn(modules),
	}
}

func getKmsKey(modules terraform.Modules) (kmskey apprunner.DescribeService) {
	for _, resource := range modules.GetResourcesByType("aws_apprunner_service") {
		kmskey = adaptKmsKey(resource, modules)
	}

	return kmskey
}

func adaptKmsKey(resource *terraform.Block, modules terraform.Modules) apprunner.DescribeService {

	return apprunner.DescribeService{
		Metadata: resource.GetMetadata(),
		KmsKey:   resource.GetAttribute("kms_key").AsStringValueOrDefault("", resource),
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

	return apprunner.ListService{
		Metadata:   resource.GetMetadata(),
		ServiceArn: resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
	}
}

package sagemaker

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sagemaker"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) sagemaker.SageMaker {
	return sagemaker.SageMaker{
		NotebookInstances: adaptInstances(modules),
	}
}

func adaptInstances(modules terraform.Modules) []sagemaker.NotebookInstance {
	var instances []sagemaker.NotebookInstance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_sagemaker_notebook_instance") {
			instances = append(instances, sagemaker.NotebookInstance{
				Metadata:             resource.GetMetadata(),
				KmsKeyId:             resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
				NetworkInterfaceId:   resource.GetAttribute("network_interface_id").AsStringValueOrDefault("", resource),
				DirectInternetAccess: resource.GetAttribute("direct_internet_access").AsStringValueOrDefault("Enabled", resource),
			})
		}
	}
	return instances
}

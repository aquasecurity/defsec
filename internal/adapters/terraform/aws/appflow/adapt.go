package appflow

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/appflow"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) appflow.Appflow {
	return appflow.Appflow{
		ListFlows: getListflow(modules),
	}
}

func getListflow(modules terraform.Modules) (flow []appflow.ListFlow) {
	for _, resource := range modules.GetResourcesByType("aws_appflow_flow") {
		flow = append(flow, adaptListFlow(resource, modules))
	}

	return flow
}

func adaptListFlow(resource *terraform.Block, modules terraform.Modules) appflow.ListFlow {

	return appflow.ListFlow{
		Metadata: resource.GetMetadata(),
		FlowName: resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		FlowArn:  resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
		KMSArn:   resource.GetAttribute("kms_arn").AsStringValueOrDefault("", resource),
	}
}

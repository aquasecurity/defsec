package appflow

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/appflow"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListflow(ctx parser.FileContext) (flow []appflow.ListFlow) {

	appflowResources := ctx.GetResourcesByType("AWS::AppFlow::Flow")

	for _, r := range appflowResources {
		afl := appflow.ListFlow{
			Metadata: r.Metadata(),
			FlowName: r.GetStringProperty("FlowName"),
			FlowArn:  r.GetStringProperty("FlowArn"),
			KMSArn:   r.GetStringProperty("KMSArn"),
		}

		flow = append(flow, afl)
	}
	return flow
}

package sagemaker

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sagemaker"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getInstances(ctx parser.FileContext) []sagemaker.NotebookInstance {

	var instances []sagemaker.NotebookInstance

	for _, r := range ctx.GetResourcesByType("AWS::SageMaker::NotebookInstance") {
		instances = append(instances, sagemaker.NotebookInstance{
			Metadata:             r.Metadata(),
			KmsKeyId:             r.GetStringProperty("KmsKeyId"),
			DirectInternetAccess: r.GetStringProperty("DirectInternetAccess"),
			NetworkInterfaceId:   types.String("", r.Metadata()),
		})
	}
	return instances
}

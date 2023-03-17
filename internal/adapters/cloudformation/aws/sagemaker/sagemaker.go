package sagemaker

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sagemaker"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) sagemaker.SageMaker {
	return sagemaker.SageMaker{
		NotebookInstances: getInstances(cfFile),
	}
}

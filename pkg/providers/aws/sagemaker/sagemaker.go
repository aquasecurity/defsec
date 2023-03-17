package sagemaker

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SageMaker struct {
	NotebookInstances []NotebookInstance
}

type NotebookInstance struct {
	Metadata             defsecTypes.Metadata
	KmsKeyId             defsecTypes.StringValue
	DirectInternetAccess defsecTypes.StringValue
	NetworkInterfaceId   defsecTypes.StringValue
}

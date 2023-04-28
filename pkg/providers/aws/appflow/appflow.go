package appflow

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Appflow struct {
	ListFlows    []ListFlow
	DescribeFlow DescribeFlow
}

type ListFlow struct {
	Metadata defsecTypes.Metadata
	FlowName defsecTypes.StringValue
	FlowArn  defsecTypes.StringValue
	KMSArn   defsecTypes.StringValue
}

type DescribeFlow struct {
	Metadata defsecTypes.Metadata
	KmsArn   defsecTypes.StringValue
}

package apprunner

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Apprunner struct {
	ListServices     []ListService
	DescribeServices DescribeService
}

type ListService struct {
	Metadata   defsecTypes.Metadata
	ServiceArn defsecTypes.StringValue
}

type DescribeService struct {
	Metadata defsecTypes.Metadata
	KmsKey   defsecTypes.StringValue
}

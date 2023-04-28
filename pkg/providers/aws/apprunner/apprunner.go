package apprunner

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Apprunner struct {
	ListServices []ListService
}

type ListService struct {
	Metadata   defsecTypes.Metadata
	ServiceArn defsecTypes.StringValue
	KmsKey     defsecTypes.StringValue
}

package cloudformation

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Cloudformation struct {
	Stacks []Stack
}

type Stack struct {
	Metadata                    defsecTypes.Metadata
	StackId                     defsecTypes.StringValue
	StackName                   defsecTypes.StringValue
	StackDriftStatus            defsecTypes.StringValue
	RoleArn                     defsecTypes.StringValue
	StackStatus                 defsecTypes.StringValue
	EnableTerminationProtection defsecTypes.BoolValue
	Parameters                  []Parameter
	StackEvents                 []StackEvent
	NotificationARNs            []defsecTypes.StringValue
}

type Parameter struct {
	Metadata     defsecTypes.Metadata
	ParameterKey defsecTypes.StringValue
}

type StackEvent struct {
	Metadata  defsecTypes.Metadata
	Timestamp defsecTypes.TimeValue
}

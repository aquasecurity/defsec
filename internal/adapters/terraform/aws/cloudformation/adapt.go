package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudformation"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) cloudformation.Cloudformation {
	return cloudformation.Cloudformation{
		Stacks: adaptStacks(modules),
	}
}

func adaptStacks(modules terraform.Modules) []cloudformation.Stack {
	var stacks []cloudformation.Stack
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudformation_stack") {
			stacks = append(stacks, adaptStack(resource))
		}
	}
	return stacks
}

func adaptStack(resource *terraform.Block) cloudformation.Stack {

	var notiarns []defsecTypes.StringValue
	arnattr := resource.GetAttribute("notification_arns")
	for _, noti := range arnattr.AsStringValues() {
		notiarns = append(notiarns, noti)
	}

	return cloudformation.Stack{
		Metadata:                    resource.GetMetadata(),
		StackId:                     resource.GetAttribute("id").AsStringValueOrDefault("", resource),
		StackName:                   resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		StackStatus:                 defsecTypes.String("", resource.GetMetadata()),
		EnableTerminationProtection: defsecTypes.Bool(false, resource.GetMetadata()),
		StackDriftStatus:            defsecTypes.String("", resource.GetMetadata()),
		RoleArn:                     resource.GetAttribute("iam_role_arn ").AsStringValueOrDefault("", resource),
		NotificationARNs:            notiarns,
		StackEvents:                 nil,
	}

}

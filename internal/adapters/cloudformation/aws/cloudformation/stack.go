package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudformation"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getStacks(cfFile parser.FileContext) []cloudformation.Stack {

	var stacks []cloudformation.Stack

	stackresources := cfFile.GetResourcesByType("AWS::CloudFormation::Stack")
	for _, r := range stackresources {

		var notiarns []types.StringValue

		for _, noti := range r.GetProperty("NotificationARNs").AsList() {
			notiarns = append(notiarns, noti.AsStringValue())
		}
		stacks = append(stacks, cloudformation.Stack{
			Metadata:                    r.Metadata(),
			StackId:                     types.String("", r.Metadata()),
			StackName:                   types.String("", r.Metadata()),
			StackDriftStatus:            types.String("", r.Metadata()),
			StackStatus:                 types.String("", r.Metadata()),
			RoleArn:                     types.String("", r.Metadata()),
			EnableTerminationProtection: types.Bool(false, r.Metadata()),
			NotificationARNs:            notiarns,
			Parameters:                  getParameters(r),
			StackEvents:                 nil,
		})
	}
	return stacks
}

func getParameters(r *parser.Resource) []cloudformation.Parameter {
	parameterProp := r.GetProperty("LoadBalancerAttributes")

	var parameters []cloudformation.Parameter
	if parameterProp.IsNotList() {
		return parameters
	}

	for _, para := range parameterProp.AsList() {
		if para.IsNotMap() {
			continue
		}
		parameters = append(parameters, cloudformation.Parameter{
			Metadata:     para.Metadata(),
			ParameterKey: types.String(para.AsMap()["Key"].AsString(), para.Metadata()),
		})
	}
	return parameters

}

package ec2

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/ec2"
	"github.com/aquasecurity/defsec/types"
)

func getInstances(ctx parser.FileContext) (instances []ec2.Instance) {

	instanceResources := ctx.GetResourceByType("AWS::EC2::Instance")

	for _, r := range instanceResources {
		instance := ec2.Instance{
			Metadata: r.Metadata(),
			// metadata not supported by CloudFormation at the moment -
			// https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/655
			MetadataOptions: ec2.MetadataOptions{},
			UserData:        r.GetStringProperty("UserData"),
			SecurityGroups:  nil,
		}
		instances = append(instances, instance)
	}

	return instances
}

func getUserData(r *parser.Resource) types.StringValue {
	userDataProp := r.GetProperty("UserData")
	if userDataProp.IsNil() || userDataProp.IsNotString() {
		return types.StringDefault("", r.Metadata())
	}
	return userDataProp.AsStringValue()
}

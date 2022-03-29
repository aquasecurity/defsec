package ec2

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getInstances(ctx parser.FileContext) (instances []ec2.Instance) {

	instanceResources := ctx.GetResourceByType("AWS::EC2::Instance")

	for _, r := range instanceResources {
		instance := ec2.Instance{
			Metadata: r.Metadata(),
			// metadata not supported by CloudFormation at the moment -
			// https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/655
			MetadataOptions: ec2.MetadataOptions{
				Metadata:     r.Metadata(),
				HttpTokens:   types.StringDefault("", r.Metadata()),
				HttpEndpoint: types.StringDefault("", r.Metadata()),
			},
			UserData:       r.GetStringProperty("UserData"),
			SecurityGroups: nil,
		}
		instances = append(instances, instance)
	}

	return instances
}

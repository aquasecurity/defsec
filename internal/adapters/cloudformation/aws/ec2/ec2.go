package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result ec2.EC2) {
	result.LaunchConfigurations = getLaunchConfigurations(cfFile)
	result.LaunchTemplates = getLaunchTemplates(cfFile)
	result.Instances = getInstances(cfFile)
	result.DefaultVPCs = nil
	result.NetworkACLs = getNetworkACLs(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)
	result.Volumes = getVolumes(cfFile)
	return result
}

package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ec2.EC2 {
	return ec2.EC2{
		LaunchConfigurations:       getLaunchConfigurations(cfFile),
		LaunchTemplates:            getLaunchTemplates(cfFile),
		Instances:                  getInstances(cfFile),
		VPCs:                       getVpcs(cfFile),
		VpcPeeringConnections:      getVpcsPeeringConnection(cfFile),
		VpcEndPoints:               getVpcsEndPoints(cfFile),
		VpcEndPointService:         getVpcEndpointServices(cfFile),
		Addresses:                  getaddresses(cfFile),
		NetworkACLs:                getNetworkACLs(cfFile),
		SecurityGroups:             getSecurityGroups(cfFile),
		Subnets:                    getSubnets(cfFile),
		Volumes:                    getVolumes(cfFile),
		RouteTables:                getRouteTables(cfFile),
		Snapshots:                  getSnapShots(cfFile),
		Images:                     getImages(cfFile),
		FlowLogs:                   getFlowlogs(cfFile),
		InternetGateways:           getinternetGateways(cfFile),
		EgressOnlyInternetGateways: getegressonlyIG(cfFile),
		VpnConnections:             getvpnConnections(cfFile),
		NatGateways:                getnatGateways(cfFile),
		VpnGateways:                getvpnGateways(cfFile),
		ResourceTags:               nil,
		NetworkInterfaces:          nil,
		AccountAttributes:          nil,
	}
}

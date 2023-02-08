package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getRouteTables(ctx parser.FileContext) (routetables []ec2.RouteTable) {

	routetableresource := ctx.GetResourcesByType("AWS::EC2::RouteTable")
	for _, r := range routetableresource {

		routetable := ec2.RouteTable{
			Metadata:     r.Metadata(),
			RouteTableId: r.GetStringProperty("RouteTableId"),
			Routes:       getroutes(ctx),
			Associations: getassosiation(ctx),
		}
		routetables = append(routetables, routetable)
	}
	return routetables
}

func getroutes(ctx parser.FileContext) []ec2.Route {

	var route []ec2.Route
	routeres := ctx.GetResourcesByType("AWS::EC2::Route")

	for _, r := range routeres {
		route = append(route, ec2.Route{
			Metadata:               r.Metadata(),
			GatewayId:              r.GetStringProperty("GatewayId"),
			VpcPeeringConnectionId: r.GetStringProperty("VpcPeeringConnectionId"),
			DestinationCidrBlock:   r.GetStringProperty("DestinationCidrBlock"),
		})
	}
	return route
}

func getassosiation(ctx parser.FileContext) []ec2.Association {

	var ass []ec2.Association
	assres := ctx.GetResourcesByType("AWS::EC2::SubnetRouteTableAssociation")
	for _, r := range assres {
		ass = append(ass, ec2.Association{
			Metadata: r.Metadata(),
			SubnetId: r.GetStringProperty("SubnetId"),
		})

	}
	return ass
}

func getaddresses(ctx parser.FileContext) (addresses []ec2.Address) {

	addresource := ctx.GetResourcesByType("AWS::EC2::EIP")
	for _, r := range addresource {

		add := ec2.Address{
			Metadata: r.Metadata(),
			Domain:   r.GetStringProperty("Domain"),
		}
		addresses = append(addresses, add)
	}
	addassresource := ctx.GetResourcesByType("AWS::EC2::EIPAssociation")
	for _, r := range addassresource {

		addass := ec2.Address{
			AllocationId:  r.GetStringProperty("AllocationId"),
			AssociationId: types.String("", r.Metadata()),
		}
		addresses = append(addresses, addass)
	}
	return addresses
}

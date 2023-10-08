package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func adaptRouteTables(modules terraform.Modules) []ec2.RouteTable {
	var routetables []ec2.RouteTable
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_route_table") {
			routetables = append(routetables, adaptRouteTable(resource, module))
		}
	}
	return routetables
}

func adaptRouteTable(resource *terraform.Block, module *terraform.Module) ec2.RouteTable {

	return ec2.RouteTable{
		Metadata:     resource.GetMetadata(),
		RouteTableId: resource.GetAttribute("id").AsStringValueOrDefault("", resource),
		Routes:       getRoutes(resource),
		Associations: getAssociatons(resource, module),
	}
}

func getRoutes(resource *terraform.Block) []ec2.Route {

	var route []ec2.Route
	for _, res := range resource.GetBlocks("route") {
		route = append(route, ec2.Route{
			Metadata:               res.GetMetadata(),
			GatewayId:              res.GetAttribute("gateway_id").AsStringValueOrDefault("", res),
			DestinationCidrBlock:   res.GetAttribute("cidr_block").AsStringValueOrDefault("", res),
			VpcPeeringConnectionId: res.GetAttribute("vpc_peering_connection_id").AsStringValueOrDefault("", res),
		})
	}
	return route
}

func getAssociatons(resource *terraform.Block, module *terraform.Module) []ec2.Association {

	assRes := module.GetReferencingResources(resource, "aws_route_table_association", "route_table_id")
	var Ass []ec2.Association
	for _, res := range assRes {
		Ass = append(Ass, ec2.Association{
			Metadata: res.GetMetadata(),
			SubnetId: res.GetAttribute("subnet_id").AsStringValueOrDefault("", res),
		})
	}
	return Ass
}

func adaptAddresses(modules terraform.Modules) []ec2.Address {
	var address []ec2.Address
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_eip") {
			address = append(address, adaptAddress(resource, module))
		}
	}
	return address
}

func adaptAddress(resource *terraform.Block, module *terraform.Module) ec2.Address {

	return ec2.Address{
		Metadata:      resource.GetMetadata(),
		Domain:        resource.GetAttribute("domain").AsStringValueOrDefault("", resource),
		AllocationId:  resource.GetAttribute("allocation_id").AsStringValueOrDefault("", resource),
		AssociationId: resource.GetAttribute("association_id").AsStringValueOrDefault("", resource),
	}
}

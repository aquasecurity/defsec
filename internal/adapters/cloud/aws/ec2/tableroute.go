package ec2

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
)

func (a *adapter) getRouteTable() ([]ec2.RouteTable, error) {

	a.Tracker().SetServiceLabel("Discovering routes...")

	var input ec2api.DescribeRouteTablesInput

	var apiRoutetables []types.RouteTable
	for {
		output, err := a.client.DescribeRouteTables(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiRoutetables = append(apiRoutetables, output.RouteTables...)
		a.Tracker().SetTotalResources(len(apiRoutetables))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting routes...")
	return concurrency.Adapt(apiRoutetables, a.RootAdapter, a.adaptRoutes), nil
}

func (a *adapter) adaptRoutes(routetable types.RouteTable) (*ec2.RouteTable, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("route/%s", *routetable.RouteTableId))

	var routelist []ec2.Route
	for _, r := range routetable.Routes {
		var gatewayId, DesCidrBlock, vpcPCID string
		if r.GatewayId != nil {
			gatewayId = *r.GatewayId
		}
		if r.DestinationCidrBlock != nil {
			DesCidrBlock = *r.DestinationCidrBlock
		}
		if r.VpcPeeringConnectionId != nil {
			vpcPCID = *r.VpcPeeringConnectionId
		}

		routelist = append(routelist, ec2.Route{
			Metadata:               metadata,
			GatewayId:              defsecTypes.String(gatewayId, metadata),
			DestinationCidrBlock:   defsecTypes.String(DesCidrBlock, metadata),
			VpcPeeringConnectionId: defsecTypes.String(vpcPCID, metadata),
		})
	}

	var associations []ec2.Association
	for _, a := range routetable.Associations {

		var subnetid string
		if a.SubnetId != nil {
			subnetid = *a.SubnetId
		}

		associations = append(associations, ec2.Association{
			Metadata: metadata,
			SubnetId: defsecTypes.String(subnetid, metadata),
		})
	}

	return &ec2.RouteTable{
		Metadata:     metadata,
		RouteTableId: defsecTypes.String(*routetable.RouteTableId, metadata),
		Routes:       routelist,
		Associations: associations,
	}, nil
}

func (a *adapter) getAddresses() ([]ec2.Address, error) {

	a.Tracker().SetServiceLabel("Discovering adresses...")

	var input ec2api.DescribeAddressesInput

	var apiaddress []types.Address
	for {
		output, err := a.client.DescribeAddresses(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiaddress = append(apiaddress, output.Addresses...)
		a.Tracker().SetTotalResources(len(apiaddress))
		if output.Addresses == nil {
			break
		}

	}

	a.Tracker().SetServiceLabel("Adapting addresses...")
	return concurrency.Adapt(apiaddress, a.RootAdapter, a.adaptAddress), nil
}

func (a *adapter) adaptAddress(address types.Address) (*ec2.Address, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("address/%s", *address.InstanceId))

	return &ec2.Address{
		Metadata:      metadata,
		AllocationId:  defsecTypes.String(*address.AllocationId, metadata),
		AssociationId: defsecTypes.String(*address.AllocationId, metadata),
		Domain:        defsecTypes.String(string(address.Domain), metadata),
	}, nil
}

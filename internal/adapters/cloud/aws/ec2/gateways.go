package ec2

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
)

func (a *adapter) getinternetGateways() ([]ec2.InternetGateway, error) {

	a.Tracker().SetServiceLabel("Discovering internet gateways...")

	var input ec2api.DescribeInternetGatewaysInput

	var apiinternetgateway []types.InternetGateway
	for {
		output, err := a.client.DescribeInternetGateways(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiinternetgateway = append(apiinternetgateway, output.InternetGateways...)
		a.Tracker().SetTotalResources(len(apiinternetgateway))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting internet gateways...")
	return concurrency.Adapt(apiinternetgateway, a.RootAdapter, a.adaptinternetgateway), nil
}

func (a *adapter) getNatGateways() ([]ec2.NatGateway, error) {

	a.Tracker().SetServiceLabel("Discovering nat gateways...")

	var input ec2api.DescribeNatGatewaysInput

	var apinatgateways []types.NatGateway
	for {
		output, err := a.client.DescribeNatGateways(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apinatgateways = append(apinatgateways, output.NatGateways...)
		a.Tracker().SetTotalResources(len(apinatgateways))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting nat gateways...")
	return concurrency.Adapt(apinatgateways, a.RootAdapter, a.adaptnatgateway), nil
}

func (a *adapter) getVpnGateways() ([]ec2.VpnGateway, error) {

	a.Tracker().SetServiceLabel("Discovering vpn gateways...")

	var input ec2api.DescribeVpnGatewaysInput

	var apiVpngateway []types.VpnGateway
	for {
		output, err := a.client.DescribeVpnGateways(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiVpngateway = append(apiVpngateway, output.VpnGateways...)
		a.Tracker().SetTotalResources(len(apiVpngateway))
		if output.VpnGateways == nil {
			break
		}

	}

	a.Tracker().SetServiceLabel("Adapting vpn gateways...")
	return concurrency.Adapt(apiVpngateway, a.RootAdapter, a.adaptvpngateway), nil
}

func (a *adapter) getEgressOnlyIGs() ([]ec2.EgressOnlyInternetGateway, error) {
	a.Tracker().SetServiceLabel("Discovering Egress only internet gateways...")

	var input ec2api.DescribeEgressOnlyInternetGatewaysInput

	var apiinternetgateway []types.EgressOnlyInternetGateway
	for {
		output, err := a.client.DescribeEgressOnlyInternetGateways(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiinternetgateway = append(apiinternetgateway, output.EgressOnlyInternetGateways...)
		a.Tracker().SetTotalResources(len(apiinternetgateway))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting Egress only internet gateways...")
	return concurrency.Adapt(apiinternetgateway, a.RootAdapter, a.adaptEgressOnlyIG), nil
}

func (a *adapter) getVpnConnections() ([]ec2.VpnConnection, error) {

	a.Tracker().SetServiceLabel("Discovering vpn Connections...")

	var input ec2api.DescribeVpnConnectionsInput

	var apiVpnConn []types.VpnConnection
	for {
		output, err := a.client.DescribeVpnConnections(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiVpnConn = append(apiVpnConn, output.VpnConnections...)
		a.Tracker().SetTotalResources(len(apiVpnConn))
		if output.VpnConnections == nil {
			break
		}

	}

	a.Tracker().SetServiceLabel("Adapting vpn connections...")
	return concurrency.Adapt(apiVpnConn, a.RootAdapter, a.adaptvpnconnection), nil
}

func (a *adapter) adaptvpnconnection(vpnConn types.VpnConnection) (*ec2.VpnConnection, error) {
	metadata := a.CreateMetadata(fmt.Sprintf("vpnconnection/%s", *vpnConn.VpnConnectionId))
	var vgwTS []defsecTypes.StringValue
	for _, s := range vpnConn.VgwTelemetry {
		vgwTS = append(vgwTS, defsecTypes.String(string(s.Status), metadata))
	}
	return &ec2.VpnConnection{
		Metadata:           metadata,
		ID:                 defsecTypes.String(*vpnConn.VpnConnectionId, metadata),
		VgwTelemetryStatus: vgwTS,
	}, nil
}

func (a *adapter) adaptEgressOnlyIG(ig types.EgressOnlyInternetGateway) (*ec2.EgressOnlyInternetGateway, error) {
	metadata := a.CreateMetadata(fmt.Sprintf("Egressonlyinternetgateway/%s", *ig.EgressOnlyInternetGatewayId))
	return &ec2.EgressOnlyInternetGateway{
		Metadata: metadata,
		Id:       defsecTypes.String(*ig.EgressOnlyInternetGatewayId, metadata),
	}, nil
}

func (a *adapter) adaptvpngateway(vpngateway types.VpnGateway) (*ec2.VpnGateway, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("vpngateway/%s", *vpngateway.VpnGatewayId))
	var attachments []ec2.GatewayAttachment

	for _, a := range vpngateway.VpcAttachments {
		attachments = append(attachments, ec2.GatewayAttachment{
			Metadata: metadata,
			VpcId:    defsecTypes.String(*a.VpcId, metadata),
			State:    defsecTypes.String(string(a.State), metadata),
		})
	}

	return &ec2.VpnGateway{
		Metadata:   metadata,
		Attachment: attachments,
	}, nil
}

func (a *adapter) adaptinternetgateway(internetgateway types.InternetGateway) (*ec2.InternetGateway, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("internetgateway/%s", *internetgateway.InternetGatewayId))

	var attachments []ec2.GatewayAttachment
	for _, a := range internetgateway.Attachments {
		attachments = append(attachments, ec2.GatewayAttachment{
			Metadata: metadata,
			VpcId:    defsecTypes.String(*a.VpcId, metadata),
			State:    defsecTypes.String(string(a.State), metadata),
		})
	}

	return &ec2.InternetGateway{
		Metadata:    metadata,
		Id:          defsecTypes.String(*internetgateway.InternetGatewayId, metadata),
		Attachments: attachments,
	}, nil
}

func (a *adapter) adaptnatgateway(natgateway types.NatGateway) (*ec2.NatGateway, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("natgateway/%s", *natgateway.NatGatewayId))

	var vpcid, subnetid string
	if natgateway.VpcId != nil {
		vpcid = *natgateway.VpcId
	}

	if natgateway.SubnetId != nil {
		subnetid = *natgateway.SubnetId
	}

	return &ec2.NatGateway{
		Metadata: metadata,
		Id:       defsecTypes.String(*natgateway.NatGatewayId, metadata),
		VpcId:    defsecTypes.String(vpcid, metadata),
		SubnetId: defsecTypes.String(subnetid, metadata),
	}, nil
}

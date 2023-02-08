package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getinternetGateways(ctx parser.FileContext) (internetgateways []ec2.InternetGateway) {

	internetgatewayresource := ctx.GetResourcesByType("AWS::EC2::InternetGateway")

	for _, r := range internetgatewayresource {

		internetgateway := ec2.InternetGateway{
			Metadata:    r.Metadata(),
			Id:          r.GetStringProperty("InternetGatewayId"),
			Attachments: getAttachments(ctx),
		}
		internetgateways = append(internetgateways, internetgateway)
	}
	return internetgateways
}

func getnatGateways(ctx parser.FileContext) (natgateways []ec2.NatGateway) {

	natgatewayresource := ctx.GetResourcesByType("AWS::EC2::NatGateway")
	for _, r := range natgatewayresource {

		natgateway := ec2.NatGateway{
			Metadata: r.Metadata(),
			Id:       r.GetStringProperty("NatGatewayId"),
			VpcId:    types.String("", r.Metadata()),
			SubnetId: r.GetStringProperty("SubnetId"),
		}
		natgateways = append(natgateways, natgateway)
	}
	return natgateways
}

func getvpnGateways(ctx parser.FileContext) (vpngateways []ec2.VpnGateway) {

	vpngatewayresource := ctx.GetResourcesByType("AWS::EC2::VPNGateway")

	for _, r := range vpngatewayresource {

		vpngateway := ec2.VpnGateway{
			Metadata:   r.Metadata(),
			Attachment: getAttachments(ctx),
		}
		vpngateways = append(vpngateways, vpngateway)
	}
	return vpngateways

}

func getvpnConnections(ctx parser.FileContext) (vpnConnection []ec2.VpnConnection) {
	var vpnConn []ec2.VpnConnection
	for _, v := range ctx.GetResourcesByType("AWS::EC2::VPNConnection") {
		vpnConn = append(vpnConn, ec2.VpnConnection{
			Metadata:           v.Metadata(),
			ID:                 v.GetStringProperty("VpnConnectionId"),
			VgwTelemetryStatus: nil,
		})
	}
	return vpnConn
}

func getegressonlyIG(ctx parser.FileContext) (eOIG []ec2.EgressOnlyInternetGateway) {

	var egressonlyIGs []ec2.EgressOnlyInternetGateway
	for _, r := range ctx.GetResourcesByType("AWS::EC2::EgressOnlyInternetGateway") {
		egressonlyIGs = append(egressonlyIGs, ec2.EgressOnlyInternetGateway{
			Metadata: r.Metadata(),
			Id:       r.GetStringProperty("ID"),
		})
	}
	return egressonlyIGs
}

func getAttachments(ctx parser.FileContext) []ec2.GatewayAttachment {
	var attch []ec2.GatewayAttachment
	for _, r := range ctx.GetResourcesByType("AWS::EC2::VPCGatewayAttachment") {
		attch = append(attch, ec2.GatewayAttachment{
			Metadata: r.Metadata(),
			VpcId:    r.GetStringProperty("VpcId"),
			State:    types.String("", r.Metadata()),
		})
	}
	return attch
}

package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func adaptInternetGateways(modules terraform.Modules) []ec2.InternetGateway {
	var internetGateway []ec2.InternetGateway
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_internet_gateway") {
			internetGateway = append(internetGateway, adaptinternetgateway(resource, module))
		}
	}
	return internetGateway
}

func adaptinternetgateway(resource *terraform.Block, module *terraform.Module) ec2.InternetGateway {

	var attachments []ec2.GatewayAttachment
	AR := module.GetReferencingResources(resource, "aws_internet_gateway_attachment", "internet_gateway_id")
	for _, r := range AR {
		attachments = append(attachments, ec2.GatewayAttachment{
			Metadata: r.GetMetadata(),
			VpcId:    r.GetAttribute("vpc_id").AsStringValueOrDefault("", r),
			State:    types.String("", r.GetMetadata()),
		})
	}

	Internetgateway := ec2.InternetGateway{
		Metadata:    resource.GetMetadata(),
		Id:          resource.GetAttribute("id").AsStringValueOrDefault("", resource),
		Attachments: attachments,
	}

	return Internetgateway
}

func adaptEgressonlyIGs(modules terraform.Modules) []ec2.EgressOnlyInternetGateway {
	var EOIGs []ec2.EgressOnlyInternetGateway
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_egress_only_internet_gateway") {
			EOIGs = append(EOIGs, adaptEgressonlyIG(resource))
		}
	}
	return EOIGs
}

func adaptEgressonlyIG(r *terraform.Block) ec2.EgressOnlyInternetGateway {
	return ec2.EgressOnlyInternetGateway{
		Metadata: r.GetMetadata(),
		Id:       r.GetAttribute("id").AsStringValueOrDefault("", r),
	}

}

func adaptNatGateways(modules terraform.Modules) []ec2.NatGateway {
	var natGateway []ec2.NatGateway
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_nat_gateway") {
			natGateway = append(natGateway, adaptnatgateway(resource))
		}
	}
	return natGateway
}

func adaptnatgateway(r *terraform.Block) ec2.NatGateway {

	return ec2.NatGateway{
		Metadata: r.GetMetadata(),
		Id:       r.GetAttribute("id").AsStringValueOrDefault("", r),
		VpcId:    types.String("", r.GetMetadata()),
		SubnetId: r.GetAttribute("subnet_id").AsStringValueOrDefault("", r),
	}
}

func adaptVpnGatways(modules terraform.Modules) []ec2.VpnGateway {
	var vpnGateway []ec2.VpnGateway
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_vpn_gateway") {
			vpnGateway = append(vpnGateway, adaptvpngateway(resource, module))
		}
	}
	return vpnGateway
}

func adaptvpngateway(resource *terraform.Block, module *terraform.Module) ec2.VpnGateway {

	var attachments []ec2.GatewayAttachment
	AR := module.GetReferencingResources(resource, "aws_vpn_gateway_attachment", "vpn_gateway_id")
	for _, r := range AR {
		attachments = append(attachments, ec2.GatewayAttachment{
			Metadata: r.GetMetadata(),
			VpcId:    r.GetAttribute("vpc_id").AsStringValueOrDefault("", r),
			State:    types.String("", r.GetMetadata()),
		})
	}

	return ec2.VpnGateway{
		Metadata:   resource.GetMetadata(),
		Attachment: attachments,
	}

}

func adaptVpnConnections(modules terraform.Modules) []ec2.VpnConnection {
	var vpnConn []ec2.VpnConnection
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_vpn_connection") {
			vpnConn = append(vpnConn, adaptVpnConnection(resource))
		}
	}
	return vpnConn
}

func adaptVpnConnection(r *terraform.Block) ec2.VpnConnection {

	var vgwTS []types.StringValue
	for _, vgw := range r.GetBlocks("vgw_telemetry") {
		statusAttr := vgw.GetAttribute("status").AsStringValueOrDefault("", vgw)
		vgwTS = append(vgwTS, statusAttr)
	}
	return ec2.VpnConnection{
		Metadata:           r.GetMetadata(),
		ID:                 r.GetAttribute("id").AsStringValueOrDefault("", r),
		VgwTelemetryStatus: vgwTS,
	}
}

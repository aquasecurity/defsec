package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type naclAdapter struct {
	naclRuleIDs terraform.ResourceIDResolutions
}

type sgAdapter struct {
	sgRuleIDs terraform.ResourceIDResolutions
}

func adaptVPCs(modules terraform.Modules) []ec2.VPC {
	var vpcs []ec2.VPC
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_default_vpc") {
			vpcs = append(vpcs, adaptVPC(modules, resource, true))
		}
		for _, resource := range module.GetResourcesByType("aws_vpc") {
			vpcs = append(vpcs, adaptVPC(modules, resource, false))
		}
	}
	return vpcs
}

func adaptVPC(modules terraform.Modules, block *terraform.Block, def bool) ec2.VPC {
	var hasFlowLogs bool
	for _, flow := range modules.GetResourcesByType("aws_flow_log") {
		vpcAttr := flow.GetAttribute("vpc_id")
		if vpcAttr.ReferencesBlock(block) {
			hasFlowLogs = true
			break
		}
	}

	return ec2.VPC{
		Metadata:        block.GetMetadata(),
		ID:              defsecTypes.StringUnresolvable(block.GetMetadata()),
		IsDefault:       defsecTypes.Bool(def, block.GetMetadata()),
		SecurityGroups:  nil,
		FlowLogsEnabled: defsecTypes.BoolDefault(hasFlowLogs, block.GetMetadata()),
		Tags:            gettags(block),
	}
}

func (a *sgAdapter) adaptSecurityGroups(modules terraform.Modules) []ec2.SecurityGroup {
	var securityGroups []ec2.SecurityGroup
	var groupname defsecTypes.StringValue
	for _, resource := range modules.GetResourcesByType("aws_security_group") {
		groupname = resource.GetAttribute("name").AsStringValueOrDefault("", resource)
		securityGroups = append(securityGroups, a.adaptSecurityGroup(resource, modules))
	}
	orphanResources := modules.GetResourceByIDs(a.sgRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := ec2.SecurityGroup{
			Metadata:     defsecTypes.NewUnmanagedMetadata(),
			GroupId:      defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			Description:  defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			GroupName:    groupname,
			IngressRules: nil,
			EgressRules:  nil,
			IsDefault:    defsecTypes.BoolUnresolvable(defsecTypes.NewUnmanagedMetadata()),
			VPCID:        defsecTypes.StringUnresolvable(defsecTypes.NewUnmanagedMetadata()),
		}
		for _, sgRule := range orphanResources {
			if sgRule.GetAttribute("type").Equals("ingress") {
				orphanage.IngressRules = append(orphanage.IngressRules, adaptSGRule(sgRule, modules))
			} else if sgRule.GetAttribute("type").Equals("egress") {
				orphanage.EgressRules = append(orphanage.EgressRules, adaptSGRule(sgRule, modules))
			}
		}
	}

	return securityGroups
}

func (a *naclAdapter) adaptNetworkACLs(modules terraform.Modules) []ec2.NetworkACL {
	var networkACLs []ec2.NetworkACL
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_network_acl") {
			networkACLs = append(networkACLs, a.adaptNetworkACL(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.naclRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := ec2.NetworkACL{
			Metadata:      defsecTypes.NewUnmanagedMetadata(),
			Rules:         nil,
			IsDefaultRule: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		}
		for _, naclRule := range orphanResources {
			orphanage.Rules = append(orphanage.Rules, adaptNetworkACLRule(naclRule))
		}
		networkACLs = append(networkACLs, orphanage)
	}

	return networkACLs
}

func (a *sgAdapter) adaptSecurityGroup(resource *terraform.Block, module terraform.Modules) ec2.SecurityGroup {
	var ingressRules []ec2.SecurityGroupRule
	var egressRules []ec2.SecurityGroupRule

	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	ingressBlocks := resource.GetBlocks("ingress")
	for _, ingressBlock := range ingressBlocks {
		ingressRules = append(ingressRules, adaptSGRule(ingressBlock, module))
	}

	egressBlocks := resource.GetBlocks("egress")
	for _, egressBlock := range egressBlocks {
		egressRules = append(egressRules, adaptSGRule(egressBlock, module))
	}

	rulesBlocks := module.GetReferencingResources(resource, "aws_security_group_rule", "security_group_id")
	for _, ruleBlock := range rulesBlocks {
		a.sgRuleIDs.Resolve(ruleBlock.ID())
		if ruleBlock.GetAttribute("type").Equals("ingress") {
			ingressRules = append(ingressRules, adaptSGRule(ruleBlock, module))
		} else if ruleBlock.GetAttribute("type").Equals("egress") {
			egressRules = append(egressRules, adaptSGRule(ruleBlock, module))
		}
	}

	return ec2.SecurityGroup{
		Metadata:     resource.GetMetadata(),
		Description:  descriptionVal,
		GroupName:    defsecTypes.String("", resource.GetMetadata()),
		GroupId:      resource.GetAttribute("id").AsStringValueOrDefault("", resource),
		IngressRules: ingressRules,
		EgressRules:  egressRules,
		IsDefault:    defsecTypes.Bool(false, defsecTypes.NewUnmanagedMetadata()),
		VPCID:        resource.GetAttribute("vpc_id").AsStringValueOrDefault("", resource),
		Tags:         gettags(resource),
	}
}

func adaptSGRule(resource *terraform.Block, modules terraform.Modules) ec2.SecurityGroupRule {
	ruleDescAttr := resource.GetAttribute("description")
	ruleDescVal := ruleDescAttr.AsStringValueOrDefault("", resource)

	var cidrs []defsecTypes.StringValue

	cidrBlocks := resource.GetAttribute("cidr_blocks")
	ipv6cidrBlocks := resource.GetAttribute("ipv6_cidr_blocks")
	varBlocks := modules.GetBlocks().OfType("variable")

	for _, vb := range varBlocks {
		if cidrBlocks.IsNotNil() && cidrBlocks.ReferencesBlock(vb) {
			cidrBlocks = vb.GetAttribute("default")
		}
		if ipv6cidrBlocks.IsNotNil() && ipv6cidrBlocks.ReferencesBlock(vb) {
			ipv6cidrBlocks = vb.GetAttribute("default")
		}
	}

	if cidrBlocks.IsNotNil() {
		cidrs = append(cidrs, cidrBlocks.AsStringValues()...)
	}

	if ipv6cidrBlocks.IsNotNil() {
		cidrs = append(cidrs, ipv6cidrBlocks.AsStringValues()...)
	}

	return ec2.SecurityGroupRule{
		Metadata:    resource.GetMetadata(),
		Description: ruleDescVal,
		FromPort:    resource.GetAttribute("from_port").AsIntValueOrDefault(0, resource),
		ToPort:      resource.GetAttribute("to_port").AsIntValueOrDefault(0, resource),
		CIDRs:       cidrs,
		IpProtocol:  resource.GetAttribute("protocol").AsStringValueOrDefault("", resource),
	}
}

func (a *naclAdapter) adaptNetworkACL(resource *terraform.Block, module *terraform.Module) ec2.NetworkACL {
	var networkRules []ec2.NetworkACLRule
	rulesBlocks := module.GetReferencingResources(resource, "aws_network_acl_rule", "network_acl_id")
	for _, ruleBlock := range rulesBlocks {
		a.naclRuleIDs.Resolve(ruleBlock.ID())
		networkRules = append(networkRules, adaptNetworkACLRule(ruleBlock))
	}
	return ec2.NetworkACL{
		Metadata:      resource.GetMetadata(),
		Rules:         networkRules,
		Entries:       nil,
		IsDefaultRule: defsecTypes.BoolDefault(false, resource.GetMetadata()),
	}
}

func adaptNetworkACLRule(resource *terraform.Block) ec2.NetworkACLRule {
	var cidrs []defsecTypes.StringValue

	typeVal := defsecTypes.StringDefault("ingress", resource.GetMetadata())

	egressAtrr := resource.GetAttribute("egress")
	if egressAtrr.IsTrue() {
		typeVal = defsecTypes.String("egress", egressAtrr.GetMetadata())
	} else if egressAtrr.IsNotNil() {
		typeVal = defsecTypes.String("ingress", egressAtrr.GetMetadata())
	}

	actionAttr := resource.GetAttribute("rule_action")
	actionVal := actionAttr.AsStringValueOrDefault("", resource)

	protocolAtrr := resource.GetAttribute("protocol")
	protocolVal := protocolAtrr.AsStringValueOrDefault("-1", resource)

	cidrAttr := resource.GetAttribute("cidr_block")
	if cidrAttr.IsNotNil() {
		cidrs = append(cidrs, cidrAttr.AsStringValueOrDefault("", resource))
	}
	ipv4cidrAttr := resource.GetAttribute("ipv6_cidr_block")
	if ipv4cidrAttr.IsNotNil() {
		cidrs = append(cidrs, ipv4cidrAttr.AsStringValueOrDefault("", resource))
	}

	return ec2.NetworkACLRule{
		Metadata: resource.GetMetadata(),
		Type:     typeVal,
		Action:   actionVal,
		Protocol: protocolVal,
		CIDRs:    cidrs,
	}
}

func adaptVPCEndPoints(modules terraform.Modules) []ec2.VpcEndPoint {
	var vpcs []ec2.VpcEndPoint
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_vpc_endpoint") {
			vpcs = append(vpcs, adaptVPCEndPoint(resource))
		}
	}
	return vpcs
}

func adaptVPCEndPoint(resource *terraform.Block) ec2.VpcEndPoint {
	var subnetIds []defsecTypes.StringValue
	subnetIdsAttr := resource.GetAttribute("subnet_ids")
	for _, subnetId := range subnetIdsAttr.AsStringValues() {
		subnetIds = append(subnetIds, subnetId)
	}
	return ec2.VpcEndPoint{
		Metadata:       resource.GetMetadata(),
		ID:             resource.GetAttribute("id").AsStringValueOrDefault("", resource),
		Type:           resource.GetAttribute("vpc_endpoint_type").AsStringValueOrDefault("", resource),
		PolicyDocument: resource.GetAttribute("policy").AsStringValueOrDefault("", resource),
		SubnetIds:      subnetIds,
	}

}

func adaptVPCPeerConnections(modules terraform.Modules) []ec2.VpcPeeringConnection {
	var vpcs []ec2.VpcPeeringConnection
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_vpc_peering_connection") {
			vpcs = append(vpcs, adaptVPCPeerConnection(resource))
		}
	}
	return vpcs
}

func adaptVPCPeerConnection(vpcinfo *terraform.Block) ec2.VpcPeeringConnection {

	return ec2.VpcPeeringConnection{
		Metadata:               vpcinfo.GetMetadata(),
		VpcPeeringConnectionId: vpcinfo.GetAttribute("id").AsStringValueOrDefault("", vpcinfo),
		AccepterVpcInfo: ec2.VpcInfo{
			Metadata:  vpcinfo.GetMetadata(),
			CidrBlock: defsecTypes.String("", vpcinfo.GetMetadata()),
			OwnerId:   vpcinfo.GetAttribute("peer_owner_id").AsStringValueOrDefault("", vpcinfo),
			VPCId:     vpcinfo.GetAttribute("peer_vpc_id").AsStringValueOrDefault("", vpcinfo),
		},
		RequesterVpcInfo: ec2.VpcInfo{
			Metadata:  vpcinfo.GetMetadata(),
			CidrBlock: defsecTypes.String("", vpcinfo.GetMetadata()),
			OwnerId:   vpcinfo.GetAttribute("peer_owner_id").AsStringValueOrDefault("", vpcinfo),
			VPCId:     vpcinfo.GetAttribute("vpc_id").AsStringValueOrDefault("", vpcinfo),
		},
	}

}

func adaptVPCEPServices(modules terraform.Modules) []ec2.VpcEndPointService {
	var vpcs []ec2.VpcEndPointService
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_vpc_endpoint_service") {
			vpcs = append(vpcs, adaptVPCEPService(resource, module))
		}
	}
	return vpcs
}

func adaptVPCEPService(eps *terraform.Block, module *terraform.Module) ec2.VpcEndPointService {

	var APs []ec2.AllowedPricipal
	for _, AP := range module.GetReferencingResources(eps, "aws_vpc_endpoint_service_allowed_principal", "vpc_endpoint_service_id") {
		APs = append(APs, ec2.AllowedPricipal{
			Metadata: AP.GetMetadata(),
		})
	}

	return ec2.VpcEndPointService{
		Metadata:                          eps.GetMetadata(),
		Owner:                             defsecTypes.String("", eps.GetMetadata()),
		ServiceId:                         eps.GetAttribute("id").AsStringValueOrDefault("", eps),
		VpcEPSPermissionAllowedPrincipals: APs,
	}
}

package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getSecurityGroups(ctx parser.FileContext) (groups []ec2.SecurityGroup) {
	for _, r := range ctx.GetResourcesByType("AWS::EC2::SecurityGroup") {

		group := ec2.SecurityGroup{
			Metadata:     r.Metadata(),
			Description:  r.GetStringProperty("GroupDescription"),
			GroupName:    r.GetStringProperty("GroupName"),
			GroupId:      types.String("", r.Metadata()),
			IngressRules: getIngressRules(r),
			EgressRules:  getEgressRules(r),
			IsDefault:    types.Bool(r.GetStringProperty("GroupName").EqualTo("default"), r.Metadata()),
			VPCID:        r.GetStringProperty("VpcId"),
			Tags:         gettags(r),
		}

		groups = append(groups, group)
	}
	return groups
}

func getVpcs(ctx parser.FileContext) (vpcs []ec2.VPC) {

	for _, r := range ctx.GetResourcesByType("AWS::EC2::VPC") {

		vpc := ec2.VPC{
			Metadata:        r.Metadata(),
			ID:              r.GetStringProperty("VpcId"),
			SecurityGroups:  nil,
			IsDefault:       types.Bool(false, r.Metadata()),
			FlowLogsEnabled: types.Bool(false, r.Metadata()),
			Tags:            gettags(r),
		}
		vpcs = append(vpcs, vpc)
	}
	return vpcs
}
func getIngressRules(r *parser.Resource) (sgRules []ec2.SecurityGroupRule) {
	if ingressProp := r.GetProperty("SecurityGroupIngress"); ingressProp.IsList() {
		for _, ingress := range ingressProp.AsList() {
			rule := ec2.SecurityGroupRule{
				Metadata:    ingress.Metadata(),
				Description: ingress.GetStringProperty("Description"),
				CIDRs:       nil,
				ToPort:      ingress.GetIntProperty("ToPort"),
				FromPort:    ingress.GetIntProperty("FromPort"),
				IpProtocol:  ingress.GetStringProperty("IpProtocol"),
			}
			v4Cidr := ingress.GetProperty("CidrIp")
			if v4Cidr.IsString() && v4Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v4Cidr.AsString(), v4Cidr.Metadata()))
			}
			v6Cidr := ingress.GetProperty("CidrIpv6")
			if v6Cidr.IsString() && v6Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v6Cidr.AsString(), v6Cidr.Metadata()))
			}

			groupid := ingress.GetProperty("")
			if groupid.IsString() && groupid.AsStringValue().IsNotEmpty() {
				rule.UserGroupIds = append(rule.UserGroupIds, types.StringExplicit(groupid.AsString(), groupid.Metadata()))
			}

			sgRules = append(sgRules, rule)
		}
	}
	return sgRules
}

func getEgressRules(r *parser.Resource) (sgRules []ec2.SecurityGroupRule) {
	if egressProp := r.GetProperty("SecurityGroupEgress"); egressProp.IsList() {
		for _, egress := range egressProp.AsList() {
			rule := ec2.SecurityGroupRule{
				Metadata:    egress.Metadata(),
				Description: egress.GetStringProperty("Description"),
				ToPort:      egress.GetIntProperty("ToPort"),
				FromPort:    egress.GetIntProperty("FromPort"),
				CIDRs:       nil,
				IpProtocol:  egress.GetStringProperty("IpProtocol"),
			}
			v4Cidr := egress.GetProperty("CidrIp")
			if v4Cidr.IsString() && v4Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v4Cidr.AsString(), v4Cidr.Metadata()))
			}
			v6Cidr := egress.GetProperty("CidrIpv6")
			if v6Cidr.IsString() && v6Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v6Cidr.AsString(), v6Cidr.Metadata()))
			}

			sgRules = append(sgRules, rule)
		}
	}
	return sgRules
}

func gettags(r *parser.Resource) []ec2.Tags {
	var tags []ec2.Tags
	for _, res := range r.GetProperty("Tags").AsList() {
		tags = append(tags, ec2.Tags{
			Metadata: res.Metadata(),
		})
	}
	return tags
}

func getVpcsPeeringConnection(ctx parser.FileContext) []ec2.VpcPeeringConnection {

	var vpcpeeringconnections []ec2.VpcPeeringConnection
	for _, vpcinfo := range ctx.GetResourcesByType("AWS::EC2::VPCPeeringConnection") {
		vpcpeeringconnections = append(vpcpeeringconnections, ec2.VpcPeeringConnection{
			Metadata:               vpcinfo.Metadata(),
			VpcPeeringConnectionId: vpcinfo.GetStringProperty("Id"),
			AccepterVpcInfo: ec2.VpcInfo{
				Metadata:  vpcinfo.Metadata(),
				CidrBlock: types.String("", vpcinfo.Metadata()),
				VPCId:     vpcinfo.GetStringProperty("PeerVpcId"),
				OwnerId:   vpcinfo.GetStringProperty("PeerOwnerId"),
			},
			RequesterVpcInfo: ec2.VpcInfo{
				Metadata:  vpcinfo.Metadata(),
				CidrBlock: types.String("", vpcinfo.Metadata()),
				VPCId:     vpcinfo.GetStringProperty("PeerVpcId"),
				OwnerId:   vpcinfo.GetStringProperty("PeerOwnerId"),
			},
		})
	}
	return vpcpeeringconnections

}

func getVpcsEndPoints(ctx parser.FileContext) []ec2.VpcEndPoint {

	var vpcEndpoints []ec2.VpcEndPoint
	for _, vpcEP := range ctx.GetResourcesByType("AWS::EC2::VPCEndpoint") {

		var subnetids []types.StringValue
		for _, s := range vpcEP.GetProperty("SubnetIds").AsList() {
			subnetids = append(subnetids, s.AsStringValue())
		}

		vpcEndpoints = append(vpcEndpoints, ec2.VpcEndPoint{
			Metadata:       vpcEP.Metadata(),
			ID:             types.String("", vpcEP.Metadata()),
			Type:           vpcEP.GetStringProperty("VpcEndpointType"),
			PolicyDocument: vpcEP.GetStringProperty("PolicyDocument"),
			SubnetIds:      subnetids,
		})
	}
	return vpcEndpoints
}

func getVpcEndpointServices(ctx parser.FileContext) []ec2.VpcEndPointService {

	var EPSs []ec2.VpcEndPointService
	var EPSPs []ec2.AllowedPricipal
	for _, EPSP := range ctx.GetResourcesByType("AWS::EC2::VPCEndpointServicePermissions") {
		for _, AP := range EPSP.GetProperty("AllowedPrincipals").AsList() {
			EPSPs = append(EPSPs, ec2.AllowedPricipal{
				Metadata: AP.Metadata(),
			})
		}
	}

	for _, EPS := range ctx.GetResourcesByType("AWS::EC2::VPCEndpointService") {
		EPSs = append(EPSs, ec2.VpcEndPointService{
			Metadata:                          EPS.Metadata(),
			ServiceId:                         types.String("", EPS.Metadata()),
			Owner:                             types.String("", EPS.Metadata()),
			VpcEPSPermissionAllowedPrincipals: EPSPs,
		})

	}
	return EPSs
}

package ec2

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2api "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (a *adapter) getSecurityGroups() (securityGroups []ec2.SecurityGroup, err error) {

	a.Tracker().SetServiceLabel("Discovering security groups...")

	var apiSecurityGroups []types.SecurityGroup
	var input ec2api.DescribeSecurityGroupsInput

	for {
		output, err := a.client.DescribeSecurityGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiSecurityGroups = append(apiSecurityGroups, output.SecurityGroups...)
		a.Tracker().SetTotalResources(len(apiSecurityGroups))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting security groups...")
	return concurrency.Adapt(apiSecurityGroups, a.RootAdapter, a.adaptSecurityGroup), nil
}

func (a *adapter) getNetworkACLs() (nacls []ec2.NetworkACL, err error) {

	a.Tracker().SetServiceLabel("Discovering network ACLs...")
	var apiNetworkACLs []types.NetworkAcl
	var input ec2api.DescribeNetworkAclsInput

	for {
		output, err := a.client.DescribeNetworkAcls(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiNetworkACLs = append(apiNetworkACLs, output.NetworkAcls...)
		a.Tracker().SetTotalResources(len(apiNetworkACLs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}
	a.Tracker().SetServiceLabel("Adapting network ACLs...")
	return concurrency.Adapt(apiNetworkACLs, a.RootAdapter, a.adaptNetworkACL), nil
}

func (a *adapter) getVPCs() (defaultVpcs []ec2.VPC, err error) {

	a.Tracker().SetServiceLabel("Discovering VPCs...")
	var apiVPCs []types.Vpc
	var input ec2api.DescribeVpcsInput

	for {
		output, err := a.client.DescribeVpcs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiVPCs = append(apiVPCs, output.Vpcs...)
		a.Tracker().SetTotalResources(len(apiVPCs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting VPCs...")
	return concurrency.Adapt(apiVPCs, a.RootAdapter, a.adaptVPC), nil
}

func (a *adapter) adaptSecurityGroup(apiSecurityGroup types.SecurityGroup) (*ec2.SecurityGroup, error) {

	sgMetadata := a.CreateMetadata("security-group/" + *apiSecurityGroup.GroupId)

	var tags []ec2.Tags
	for range apiSecurityGroup.Tags {
		tags = append(tags, ec2.Tags{
			Metadata: sgMetadata,
		})
	}

	sg := &ec2.SecurityGroup{
		Metadata:    sgMetadata,
		GroupName:   defsecTypes.String(*apiSecurityGroup.GroupName, sgMetadata),
		GroupId:     defsecTypes.String(*apiSecurityGroup.GroupId, sgMetadata),
		IsDefault:   defsecTypes.BoolDefault(apiSecurityGroup.GroupName != nil && *apiSecurityGroup.GroupName == "default", sgMetadata),
		Description: defsecTypes.String(aws.ToString(apiSecurityGroup.Description), sgMetadata),
		VPCID:       defsecTypes.StringDefault("", sgMetadata),
		Tags:        tags,
	}

	if apiSecurityGroup.VpcId != nil {
		sg.VPCID = defsecTypes.String(*apiSecurityGroup.VpcId, sgMetadata)
	}

	for _, ingress := range apiSecurityGroup.IpPermissions {

		var cidrs []defsecTypes.StringValue
		var description defsecTypes.StringValue
		if ingress.IpRanges != nil {
			for _, ipv4Range := range ingress.IpRanges {
				description = defsecTypes.String(aws.ToString(ipv4Range.Description), sgMetadata)
				cidrs = []defsecTypes.StringValue{defsecTypes.String(aws.ToString(ipv4Range.CidrIp), sgMetadata)}
			}
		}
		if ingress.Ipv6Ranges != nil {
			for _, ipv6Range := range ingress.Ipv6Ranges {
				description = defsecTypes.String(aws.ToString(ipv6Range.Description), sgMetadata)
				cidrs = []defsecTypes.StringValue{defsecTypes.String(aws.ToString(ipv6Range.CidrIpv6), sgMetadata)}
			}
		}

		var fromport, toport int
		fromport = int(*ingress.FromPort)
		toport = int(*ingress.ToPort)

		var groupids []defsecTypes.StringValue
		if ingress.UserIdGroupPairs != nil {
			for _, groupid := range ingress.UserIdGroupPairs {
				groupids = append(groupids, defsecTypes.String(*groupid.GroupId, sgMetadata))
			}
		}

		sg.IngressRules = append(sg.IngressRules, ec2.SecurityGroupRule{
			Metadata:     sgMetadata,
			IpProtocol:   defsecTypes.String(*ingress.IpProtocol, sgMetadata),
			ToPort:       defsecTypes.Int(toport, sgMetadata),
			FromPort:     defsecTypes.Int(fromport, sgMetadata),
			Description:  description,
			CIDRs:        cidrs,
			UserGroupIds: groupids,
		})

	}

	for _, egress := range apiSecurityGroup.IpPermissionsEgress {

		var cidrs []defsecTypes.StringValue
		var description defsecTypes.StringValue
		if egress.IpRanges != nil {
			for _, ipv4Range := range egress.IpRanges {
				description = defsecTypes.String(aws.ToString(ipv4Range.Description), sgMetadata)
				cidrs = []defsecTypes.StringValue{defsecTypes.String(aws.ToString(ipv4Range.CidrIp), sgMetadata)}
			}
		}
		if egress.Ipv6Ranges != nil {
			for _, ipv6Range := range egress.Ipv6Ranges {
				description = defsecTypes.String(aws.ToString(ipv6Range.Description), sgMetadata)
				cidrs = []defsecTypes.StringValue{defsecTypes.String(aws.ToString(ipv6Range.CidrIpv6), sgMetadata)}
			}
		}
		var fromport, toport int
		fromport = int(*egress.FromPort)
		toport = int(*egress.ToPort)

		sg.EgressRules = append(sg.EgressRules, ec2.SecurityGroupRule{
			Metadata:    sgMetadata,
			IpProtocol:  defsecTypes.String(*egress.IpProtocol, sgMetadata),
			ToPort:      defsecTypes.Int(toport, sgMetadata),
			FromPort:    defsecTypes.Int(fromport, sgMetadata),
			Description: description,
			CIDRs:       cidrs,
		})
	}

	return sg, nil

}

func (a *adapter) adaptNetworkACL(apiNacl types.NetworkAcl) (*ec2.NetworkACL, error) {

	naclMetadata := a.CreateMetadata("network-acl/" + *apiNacl.NetworkAclId)

	nacl := &ec2.NetworkACL{
		Metadata:      naclMetadata,
		IsDefaultRule: defsecTypes.BoolDefault(false, naclMetadata),
	}

	for _, entry := range apiNacl.Entries {
		naclType := "ingress"
		if aws.ToBool(entry.Egress) {
			naclType = "egress"
		}

		var to, from int
		if entry.PortRange != nil {
			to = int(*entry.PortRange.To)
			from = int(*entry.PortRange.From)
		}

		nacl.Entries = append(nacl.Entries, ec2.Entries{
			Metadata:   naclMetadata,
			Egress:     defsecTypes.Bool(*entry.Egress, naclMetadata),
			RuleAction: defsecTypes.String(string(entry.RuleAction), naclMetadata),
			PortRange: ec2.PortRange{
				Metadata: naclMetadata,
				To:       defsecTypes.Int(to, naclMetadata),
				From:     defsecTypes.Int(from, naclMetadata),
			},
		})

		nacl.Rules = append(nacl.Rules, ec2.NetworkACLRule{
			Metadata: naclMetadata,
			Action:   defsecTypes.String(string(entry.RuleAction), naclMetadata),
			Protocol: defsecTypes.String(aws.ToString(entry.Protocol), naclMetadata),
			Type:     defsecTypes.String(naclType, naclMetadata),
			CIDRs:    []defsecTypes.StringValue{defsecTypes.String(aws.ToString(entry.CidrBlock), naclMetadata)},
		})
	}
	return nacl, nil
}

func (a *adapter) adaptVPC(v types.Vpc) (*ec2.VPC, error) {

	vpcMetadata := a.CreateMetadata("vpc/" + *v.VpcId)

	var tags []ec2.Tags
	for range v.Tags {
		tags = append(tags, ec2.Tags{
			Metadata: vpcMetadata,
		})
	}

	vpc := &ec2.VPC{
		Metadata:        vpcMetadata,
		ID:              defsecTypes.String(*v.VpcId, vpcMetadata),
		IsDefault:       defsecTypes.BoolDefault(false, vpcMetadata),
		FlowLogsEnabled: defsecTypes.BoolDefault(false, vpcMetadata),
		Tags:            tags,
		SecurityGroups:  nil, // we link these up afterwards
	}

	if v.IsDefault != nil {
		vpc.IsDefault = defsecTypes.BoolDefault(*v.IsDefault, vpcMetadata)
	}

	logs, err := a.client.DescribeFlowLogs(a.Context(), &ec2api.DescribeFlowLogsInput{
		Filter: []types.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []string{*v.VpcId},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if logs != nil && len(logs.FlowLogs) > 0 {
		vpc.FlowLogsEnabled = defsecTypes.BoolDefault(true, vpcMetadata)
	}

	return vpc, nil

}

func (a *adapter) getVPCEndPoints() (vpcEps []ec2.VpcEndPoint, err error) {

	a.Tracker().SetServiceLabel("Discovering Vpc EndPoints...")

	var apiVpcEP []types.VpcEndpoint
	var input ec2api.DescribeVpcEndpointsInput

	for {
		output, err := a.client.DescribeVpcEndpoints(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiVpcEP = append(apiVpcEP, output.VpcEndpoints...)
		a.Tracker().SetTotalResources(len(apiVpcEP))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting Vpc EndPoints...")
	return concurrency.Adapt(apiVpcEP, a.RootAdapter, a.adaptVpcEndPoints), nil
}

func (a *adapter) adaptVpcEndPoints(vpc types.VpcEndpoint) (*ec2.VpcEndPoint, error) {
	metadata := a.CreateMetadata("vpc/" + *vpc.VpcEndpointId)

	var PD string
	if vpc.PolicyDocument != nil {
		PD = *vpc.PolicyDocument
	}

	var subnetids []defsecTypes.StringValue
	for _, s := range vpc.SubnetIds {
		subnetids = append(subnetids, defsecTypes.String(s, metadata))
	}

	return &ec2.VpcEndPoint{
		Metadata:       metadata,
		ID:             defsecTypes.String(*vpc.VpcEndpointId, metadata),
		Type:           defsecTypes.String(string(vpc.VpcEndpointType), metadata),
		PolicyDocument: defsecTypes.String(PD, metadata),
		SubnetIds:      subnetids,
	}, nil
}

func (a *adapter) getVPCPeerConnection() (vpcPcs []ec2.VpcPeeringConnection, err error) {

	a.Tracker().SetServiceLabel("Discovering Vpc PeeringConnection...")

	var apiVpcPC []types.VpcPeeringConnection
	var input ec2api.DescribeVpcPeeringConnectionsInput

	for {
		output, err := a.client.DescribeVpcPeeringConnections(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiVpcPC = append(apiVpcPC, output.VpcPeeringConnections...)
		a.Tracker().SetTotalResources(len(apiVpcPC))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting Vpc PeeringConnection...")
	return concurrency.Adapt(apiVpcPC, a.RootAdapter, a.adaptVPCPeerConnection), nil
}

func (a *adapter) adaptVPCPeerConnection(vpc types.VpcPeeringConnection) (*ec2.VpcPeeringConnection, error) {
	vpcMetadata := a.CreateMetadata("vpc/" + *vpc.VpcPeeringConnectionId)

	return &ec2.VpcPeeringConnection{
		Metadata:               vpcMetadata,
		VpcPeeringConnectionId: defsecTypes.String(*vpc.VpcPeeringConnectionId, vpcMetadata),
		AccepterVpcInfo: ec2.VpcInfo{
			Metadata:  vpcMetadata,
			CidrBlock: defsecTypes.String(*vpc.AccepterVpcInfo.CidrBlock, vpcMetadata),
			VPCId:     defsecTypes.String(*vpc.AccepterVpcInfo.VpcId, vpcMetadata),
			OwnerId:   defsecTypes.String(*vpc.AccepterVpcInfo.OwnerId, vpcMetadata),
		},
		RequesterVpcInfo: ec2.VpcInfo{
			Metadata:  vpcMetadata,
			CidrBlock: defsecTypes.String(*vpc.RequesterVpcInfo.CidrBlock, vpcMetadata),
			VPCId:     defsecTypes.String(*vpc.RequesterVpcInfo.VpcId, vpcMetadata),
			OwnerId:   defsecTypes.String(*vpc.RequesterVpcInfo.OwnerId, vpcMetadata),
		},
	}, nil
}

func (a *adapter) getVPCEPServices() (vpcEpss []ec2.VpcEndPointService, err error) {

	a.Tracker().SetServiceLabel("Discovering Vpc EndPointServices...")

	var apiVpcEpss []types.ServiceDetail
	var input ec2api.DescribeVpcEndpointServicesInput

	for {
		output, err := a.client.DescribeVpcEndpointServices(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiVpcEpss = append(apiVpcEpss, output.ServiceDetails...)
		a.Tracker().SetTotalResources(len(apiVpcEpss))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting Vpc PeeringConnection...")
	return concurrency.Adapt(apiVpcEpss, a.RootAdapter, a.adaptVPCService), nil
}

func (a *adapter) adaptVPCService(es types.ServiceDetail) (*ec2.VpcEndPointService, error) {

	var EPSPs []ec2.AllowedPricipal
	EPSP, err := a.client.DescribeVpcEndpointServicePermissions(a.Context(), &ec2api.DescribeVpcEndpointServicePermissionsInput{
		ServiceId: es.ServiceId,
	})
	if err != nil {
		return nil, err
	}

	for _, ESP := range EPSP.AllowedPrincipals {
		metadata := a.CreateMetadata("vpc/" + *ESP.ServiceId)
		EPSPs = append(EPSPs, ec2.AllowedPricipal{
			Metadata: metadata,
		})
	}
	metadata := a.CreateMetadata("vpc/" + *es.ServiceId)
	return &ec2.VpcEndPointService{
		Metadata:                          metadata,
		ServiceId:                         defsecTypes.String(*es.ServiceId, metadata),
		Owner:                             defsecTypes.String(*es.Owner, metadata),
		VpcEPSPermissionAllowedPrincipals: EPSPs,
	}, nil

}

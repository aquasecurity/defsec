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
		output, err := a.api.DescribeSecurityGroups(a.Context(), &input)
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

	a.Tracker().SetServiceLabel("Scanning network ACLs...")
	var apiNetworkACLs []types.NetworkAcl
	var input ec2api.DescribeNetworkAclsInput

	for {
		output, err := a.api.DescribeNetworkAcls(a.Context(), &input)
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

func (a *adapter) getDefaultVPCs() (defaultVpcs []ec2.DefaultVPC, err error) {

	a.Tracker().SetServiceLabel("Scanning default VPCs...")
	var apiDefaultVPCs []types.Vpc
	var input ec2api.DescribeVpcsInput

	for {
		output, err := a.api.DescribeVpcs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDefaultVPCs = append(apiDefaultVPCs, output.Vpcs...)
		a.Tracker().SetTotalResources(len(apiDefaultVPCs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting default VPCs...")
	return concurrency.Adapt(apiDefaultVPCs, a.RootAdapter, a.adaptVPC), nil
}

func (a *adapter) adaptSecurityGroup(apiSecurityGroup types.SecurityGroup) (*ec2.SecurityGroup, error) {

	sgMetadata := a.CreateMetadata(*apiSecurityGroup.GroupId)

	sg := &ec2.SecurityGroup{
		Metadata:    sgMetadata,
		Description: defsecTypes.String(aws.ToString(apiSecurityGroup.Description), sgMetadata),
	}

	for _, ingress := range apiSecurityGroup.IpPermissions {

		for _, ipRange := range ingress.IpRanges {
			sg.IngressRules = append(sg.IngressRules, ec2.SecurityGroupRule{
				Metadata:    sgMetadata,
				Description: defsecTypes.String(aws.ToString(ipRange.Description), sgMetadata),
				CIDRs:       []defsecTypes.StringValue{defsecTypes.String(aws.ToString(ipRange.CidrIp), sgMetadata)},
			})
		}
	}

	for _, egress := range apiSecurityGroup.IpPermissions {

		for _, ipRange := range egress.IpRanges {
			sg.EgressRules = append(sg.EgressRules, ec2.SecurityGroupRule{
				Metadata:    sgMetadata,
				Description: defsecTypes.String(aws.ToString(ipRange.Description), sgMetadata),
				CIDRs:       []defsecTypes.StringValue{defsecTypes.String(aws.ToString(ipRange.CidrIp), sgMetadata)},
			})
		}
	}

	return sg, nil

}

func (a *adapter) adaptNetworkACL(apiNacl types.NetworkAcl) (*ec2.NetworkACL, error) {

	naclMetadata := a.CreateMetadata(*apiNacl.NetworkAclId)

	nacl := &ec2.NetworkACL{
		Metadata:      naclMetadata,
		IsDefaultRule: defsecTypes.BoolDefault(false, naclMetadata),
	}

	for _, entry := range apiNacl.Entries {
		naclType := "ingress"
		if aws.ToBool(entry.Egress) {
			naclType = "egress"
		}

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

func (a *adapter) adaptVPC(v types.Vpc) (*ec2.DefaultVPC, error) {

	if aws.ToBool(v.IsDefault) {

		vpcMetadata := a.CreateMetadata(*v.VpcId)

		return &ec2.DefaultVPC{
			Metadata: vpcMetadata,
		}, nil
	}

	return nil, nil

}

package vpc

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/vpc"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aws/aws-sdk-go-v2/aws"
	vpcApi "github.com/aws/aws-sdk-go-v2/service/ec2"
)

type adapter struct {
	*aws2.RootAdapter
	api *vpcApi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a adapter) Name() string {
	return "vpc"
}

func (a adapter) Provider() string {
	return "aws"
}

func (a adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = vpcApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.VPC.SecurityGroups, err = a.getSecurityGroups()
	if err != nil {
		return err
	}

	state.AWS.VPC.NetworkACLs, err = a.getNetworkACLs()
	if err != nil {
		return err
	}

	state.AWS.VPC.DefaultVPCs, err = a.getDefaultVPCs()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getSecurityGroups() (securityGroups []vpc.SecurityGroup, err error) {

	a.Tracker().SetServiceLabel("Scanning VPC security groups...")

	batchSecurityGroups, token, err := a.getSecurityGroupBatch(nil)
	securityGroups = append(securityGroups, batchSecurityGroups...)

	for token != nil {
		batchSecurityGroups, token, err = a.getSecurityGroupBatch(token)
		if err != nil {
			return securityGroups, err
		}
		securityGroups = append(securityGroups, batchSecurityGroups...)
	}

	return securityGroups, nil
}

func (a *adapter) getNetworkACLs() (nacls []vpc.NetworkACL, err error) {

	a.Tracker().SetServiceLabel("Scanning VPC network ACLs...")

	batchNacls, token, err := a.getNetworkACLBatch(nil)
	nacls = append(nacls, batchNacls...)

	for token != nil {
		batchNacls, token, err = a.getNetworkACLBatch(token)
		if err != nil {
			return nacls, err
		}
		nacls = append(nacls, batchNacls...)
	}

	return nacls, nil
}

func (a *adapter) getDefaultVPCs() (defaultVpcs []vpc.DefaultVPC, err error) {

	a.Tracker().SetServiceLabel("Scanning VPC default VPCs...")

	batchDefaultVpcs, token, err := a.getDefaultVPCsBatch(nil)
	defaultVpcs = append(defaultVpcs, batchDefaultVpcs...)

	for token != nil {
		batchDefaultVpcs, token, err = a.getDefaultVPCsBatch(token)
		if err != nil {
			return defaultVpcs, err
		}
		defaultVpcs = append(defaultVpcs, batchDefaultVpcs...)
	}

	return defaultVpcs, nil

}

func (a *adapter) getSecurityGroupBatch(token *string) (securityGroups []vpc.SecurityGroup, nextToken *string, err error) {

	input := &vpcApi.DescribeSecurityGroupsInput{}

	if token != nil {
		input.NextToken = token
	}

	apiSecurityGroups, err := a.api.DescribeSecurityGroups(a.Context(), input)
	if err != nil {
		return securityGroups, nil, err
	}

	for _, apiSecurityGroup := range apiSecurityGroups.SecurityGroups {

		sgMetadata := a.CreateMetadata(*apiSecurityGroup.GroupId)

		sg := vpc.SecurityGroup{
			Metadata:    sgMetadata,
			Description: types.String(aws.ToString(apiSecurityGroup.Description), sgMetadata),
		}

		for _, ingress := range apiSecurityGroup.IpPermissions {

			for _, ipRange := range ingress.IpRanges {
				sg.IngressRules = append(sg.IngressRules, vpc.SecurityGroupRule{
					Metadata:    sgMetadata,
					Description: types.String(aws.ToString(ipRange.Description), sgMetadata),
					CIDRs:       []types.StringValue{types.String(aws.ToString(ipRange.CidrIp), sgMetadata)},
				})
			}
		}

		for _, egress := range apiSecurityGroup.IpPermissions {

			for _, ipRange := range egress.IpRanges {
				sg.EgressRules = append(sg.IngressRules, vpc.SecurityGroupRule{
					Metadata:    sgMetadata,
					Description: types.String(aws.ToString(ipRange.Description), sgMetadata),
					CIDRs:       []types.StringValue{types.String(aws.ToString(ipRange.CidrIp), sgMetadata)},
				})
			}
		}

		securityGroups = append(securityGroups, sg)

		a.Tracker().IncrementResource()
	}

	return securityGroups, apiSecurityGroups.NextToken, nil
}

func (a *adapter) getNetworkACLBatch(token *string) (nacls []vpc.NetworkACL, nextToken *string, err error) {

	input := &vpcApi.DescribeNetworkAclsInput{}

	if token != nil {
		input.NextToken = token
	}

	apiNacls, err := a.api.DescribeNetworkAcls(a.Context(), input)
	if err != nil {
		return nacls, nil, err
	}

	for _, apiNacl := range apiNacls.NetworkAcls {

		naclMetadata := a.CreateMetadata(*apiNacl.NetworkAclId)

		nacl := vpc.NetworkACL{
			Metadata: naclMetadata,
		}

		for _, entry := range apiNacl.Entries {

			naclType := "ingress"
			if aws.ToBool(entry.Egress) {
				naclType = "egress"
			}

			nacl.Rules = append(nacl.Rules, vpc.NetworkACLRule{
				Metadata: naclMetadata,
				Action:   types.String(string(entry.RuleAction), naclMetadata),
				Protocol: types.String(aws.ToString(entry.Protocol), naclMetadata),
				Type:     types.String(naclType, naclMetadata),
				CIDRs:    []types.StringValue{types.String(aws.ToString(entry.CidrBlock), naclMetadata)},
			})
		}

		a.Tracker().IncrementResource()
	}

	return nacls, apiNacls.NextToken, nil
}

func (a *adapter) getDefaultVPCsBatch(token *string) (defaultVPCs []vpc.DefaultVPC, nextToken *string, err error) {

	input := &vpcApi.DescribeVpcsInput{}

	if token != nil {
		input.NextToken = token
	}

	apiVpcs, err := a.api.DescribeVpcs(a.Context(), input)
	if err != nil {
		return defaultVPCs, nil, err
	}

	for _, v := range apiVpcs.Vpcs {
		if aws.ToBool(v.IsDefault) {

			vpcMetadata := a.CreateMetadata(*v.VpcId)

			defaultVPCs = append(defaultVPCs, vpc.DefaultVPC{
				Metadata: vpcMetadata,
			})
		}
	}

	return defaultVPCs, apiVpcs.NextToken, nil

}

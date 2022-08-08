package ec2

import (
	"strconv"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getNetworkACLs(ctx parser.FileContext) (acls []ec2.NetworkACL) {
	for _, aclResource := range ctx.GetResourcesByType("AWS::EC2::NetworkAcl") {
		acl := ec2.NetworkACL{
			Metadata:      aclResource.Metadata(),
			Rules:         getRules(aclResource.ID(), ctx),
			IsDefaultRule: types.BoolDefault(false, aclResource.Metadata()),
		}
		acls = append(acls, acl)
	}
	return acls
}

func getRules(id string, ctx parser.FileContext) (rules []ec2.NetworkACLRule) {
	for _, ruleResource := range ctx.GetResourcesByType("AWS::EC2::NetworkAclEntry") {
		aclID := ruleResource.GetProperty("NetworkAclId")
		if aclID.IsString() && aclID.AsString() == id {

			rule := ec2.NetworkACLRule{
				Metadata: ruleResource.Metadata(),
				Type:     types.StringDefault(ec2.TypeIngress, ruleResource.Metadata()),
				Action:   types.StringDefault(ec2.ActionAllow, ruleResource.Metadata()),
				Protocol: types.String("-1", ruleResource.Metadata()),
				CIDRs:    nil,
			}

			if egressProperty := ruleResource.GetProperty("Egress"); egressProperty.IsBool() {
				if egressProperty.AsBool() {
					rule.Type = types.String(ec2.TypeEgress, egressProperty.Metadata())
				} else {
					rule.Type = types.String(ec2.TypeIngress, egressProperty.Metadata())
				}
			}

			if actionProperty := ruleResource.GetProperty("RuleAction"); actionProperty.IsString() {
				if actionProperty.AsString() == ec2.ActionAllow {
					rule.Action = types.String(ec2.ActionAllow, actionProperty.Metadata())
				} else {
					rule.Action = types.String(ec2.ActionDeny, actionProperty.Metadata())
				}
			}

			if protocolProperty := ruleResource.GetProperty("Protocol"); protocolProperty.IsInt() {
				protocol := protocolProperty.AsIntValue().Value()
				rule.Protocol = types.String(strconv.Itoa(protocol), protocolProperty.Metadata())
			}

			if ipv4Cidr := ruleResource.GetProperty("CidrBlock"); ipv4Cidr.IsString() {
				rule.CIDRs = append(rule.CIDRs, ipv4Cidr.AsStringValue())
			}

			if ipv6Cidr := ruleResource.GetProperty("Ipv6CidrBlock"); ipv6Cidr.IsString() {
				rule.CIDRs = append(rule.CIDRs, ipv6Cidr.AsStringValue())
			}

			rules = append(rules, rule)
		}
	}
	return rules
}

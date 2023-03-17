package route53

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/route53"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) route53.Route53 {
	return route53.Route53{
		RecordSets: adaptRecordSets(modules),
		Domains:    adaptDomains(modules),
	}
}

func adaptRecordSets(modules terraform.Modules) []route53.RecordSet {
	var records []route53.RecordSet
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_route53_record") {
			records = append(records, adaptRecordSet(resource))
		}
	}
	return records
}

func adaptRecordSet(resource *terraform.Block) route53.RecordSet {

	var records []types.StringValue
	recordAttr := resource.GetAttribute("records")
	for _, r := range recordAttr.AsStringValues() {
		records = append(records, r)
	}

	var dnsName types.StringValue
	if aliasBlock := resource.GetBlock("alias"); aliasBlock.IsNotNil() {
		dnsName = aliasBlock.GetAttribute("name").AsStringValueOrDefault("", aliasBlock)
	}

	return route53.RecordSet{
		Metadata:        resource.GetMetadata(),
		Name:            resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Type:            resource.GetAttribute("type").AsStringValueOrDefault("", resource),
		ResourceRecords: records,
		AliasTarget: route53.AliasTarget{
			Metadata: resource.GetMetadata(),
			DnsName:  dnsName,
		},
	}

}

func adaptDomains(modules terraform.Modules) []route53.Domain {
	var domains []route53.Domain
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_route53domains_registered_domain") {
			domains = append(domains, route53.Domain{
				Metadata:          resource.GetMetadata(),
				Name:              resource.GetAttribute("domain_name").AsStringValueOrDefault("", resource),
				AutoRenew:         resource.GetAttribute("auto_renew").AsBoolValueOrDefault(true, resource),
				Expiry:            types.TimeUnresolvable(resource.GetMetadata()),
				RegistrantPrivacy: resource.GetAttribute("registrant_privacy").AsBoolValueOrDefault(true, resource),
			})
		}
	}
	return domains
}

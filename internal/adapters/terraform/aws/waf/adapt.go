package waf

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/waf"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) waf.Waf {
	return waf.Waf{
		ListWebACLs: adaptWebACLsList(modules),
	}
}

func adaptWebACLsList(modules terraform.Modules) []waf.ListACLs {
	var webACLsInfo []waf.ListACLs
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_waf_web_acl") {
			webACLsInfo = append(webACLsInfo, adaptWebACLsListID(resource))
		}
	}
	return webACLsInfo
}

func adaptWebACLsListID(resource *terraform.Block) waf.ListACLs {

	aclinfo := waf.ListACLs{
		Metadata:  resource.GetMetadata(),
		WebACLsID: resource.GetAttribute("id").AsStringValueOrDefault("", resource),
	}

	return aclinfo
}

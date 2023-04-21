package wafv2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/wafv2"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) wafv2.Wafv2 {
	return wafv2.Wafv2{
		ListWebACLs: adaptWebACLs2List(modules),
	}
}

func adaptWebACLs2List(modules terraform.Modules) []wafv2.WebACLs2 {
	var webACLsInfo []wafv2.WebACLs2
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_wafv2_web_acl") {
			webACLsInfo = append(webACLsInfo, adaptWebACLs2ListID(resource))
		}
	}
	return webACLsInfo
}

func adaptWebACLs2ListID(resource *terraform.Block) wafv2.WebACLs2 {

	aclinfo := wafv2.WebACLs2{
		Metadata: resource.GetMetadata(),
		WebACLId: resource.GetAttribute("id").AsStringValueOrDefault("", resource),
	}

	return aclinfo
}

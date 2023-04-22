package wafv2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/wafv2"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListWebACLs2(ctx parser.FileContext) (webACLInfo []wafv2.WebACLs2) {

	webACLResources := ctx.GetResourcesByType("AWS::WAFv2::WebACL")

	for _, r := range webACLResources {
		webACLInfos := wafv2.WebACLs2{
			Metadata: r.Metadata(),
			WebACLId: r.GetStringProperty("Id"),
		}

		webACLInfo = append(webACLInfo, webACLInfos)
	}

	return webACLInfo
}

package waf

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/waf"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListWebACLs(ctx parser.FileContext) (webACLInfo []waf.ListACLs) {

	webACLResources := ctx.GetResourcesByType("AWS::WAF::WebACL")

	for _, r := range webACLResources {
		webACLs := waf.ListACLs{
			Metadata:  r.Metadata(),
			WebACLsID: r.GetStringProperty("WebACLId"),
		}

		webACLInfo = append(webACLInfo, webACLs)
	}

	return webACLInfo
}

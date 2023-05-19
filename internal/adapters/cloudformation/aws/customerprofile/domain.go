package customerprofile

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/customerprofiles"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getDomain(ctx parser.FileContext) []customerprofiles.Domain {

	resources := ctx.GetResourcesByType("AWS::CustomerProfiles::Domain")
	var domains []customerprofiles.Domain
	for _, r := range resources {
		domains = append(domains, customerprofiles.Domain{
			Metadata:             r.Metadata(),
			DefaultEncryptionKey: r.GetStringProperty("DefaultEncryptionKey"),
		})
	}
	return domains
}

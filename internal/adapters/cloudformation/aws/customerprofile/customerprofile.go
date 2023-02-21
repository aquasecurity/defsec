package customerprofile

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/customerprofiles"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) customerprofiles.Customerprofiles {
	return customerprofiles.Customerprofiles{
		Domains: getDomain(cfFile),
	}
}

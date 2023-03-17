package route53

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/route53"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) route53.Route53 {
	return route53.Route53{
		RecordSets: getRecordsets(cfFile),
		Domains:    nil,
	}
}

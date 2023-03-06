package route53

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/route53"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getRecordsets(ctx parser.FileContext) []route53.RecordSet {

	var records []route53.RecordSet

	for _, r := range ctx.GetResourcesByType("AWS::Route53::RecordSet") {

		var resourceRecords []defsecTypes.StringValue
		for _, record := range r.GetProperty("ResourceRecords").AsList() {
			resourceRecords = append(resourceRecords, record.AsStringValue())
		}
		records = append(records, route53.RecordSet{
			Metadata:        r.Metadata(),
			Name:            r.GetStringProperty("Name"),
			Type:            r.GetStringProperty("Type"),
			ResourceRecords: resourceRecords,
			AliasTarget: route53.AliasTarget{
				DnsName: r.GetStringProperty("AliasTarget.DNSName"),
			},
		})
	}
	return records
}

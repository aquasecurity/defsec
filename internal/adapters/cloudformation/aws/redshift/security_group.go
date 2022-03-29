package redshift

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getSecurityGroups(ctx parser.FileContext) (groups []redshift.SecurityGroup) {
	for _, groupResource := range ctx.GetResourceByType("AWS::Redshift::ClusterSecurityGroup") {
		var group redshift.SecurityGroup
		group.Metadata = groupResource.Metadata()
		if descProp := groupResource.GetProperty("Description"); descProp.IsString() {
			group.Description = descProp.AsStringValue()
		} else {
			group.Description = types.StringDefault("", groupResource.Metadata())
		}
		groups = append(groups, group)
	}
	return groups
}

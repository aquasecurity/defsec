package elasticache

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

func getSecurityGroups(ctx parser.FileContext) (securityGroups []elasticache.SecurityGroup) {

	sgResources := ctx.GetResourceByType("AWS::ElastiCache::SecurityGroup")

	for _, r := range sgResources {

		sg := elasticache.SecurityGroup{
			Metadata:    r.Metadata(),
			Description: r.GetStringProperty("Description"),
		}
		securityGroups = append(securityGroups, sg)
	}

	return securityGroups
}

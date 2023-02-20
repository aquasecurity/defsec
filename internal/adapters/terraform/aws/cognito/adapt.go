package cognito

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cognito"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) cognito.Cognito {
	return cognito.Cognito{
		UserPool: adaptPools(modules),
	}
}

func adaptPools(modules terraform.Modules) []cognito.UserPool {
	var pools []cognito.UserPool
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cognito_user_pool") {
			pools = append(pools, cognito.UserPool{
				Metadata:         resource.GetMetadata(),
				Id:               resource.GetAttribute("id").AsStringValueOrDefault("", resource),
				MfaConfiguration: resource.GetAttribute("  mfa_configuration ").AsStringValueOrDefault("OFF", resource),
			})
		}
	}
	return pools
}

package s3glacier

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/s3glacier"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) s3glacier.S3glacier {
	return s3glacier.S3glacier{
		Vaults: adaptVaults(modules),
	}
}

func adaptVaults(modules terraform.Modules) []s3glacier.Vault {
	var vaults []s3glacier.Vault
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_glacier_vault") {
			vaults = append(vaults, s3glacier.Vault{
				Metadata: resource.GetMetadata(),
				Policy:   resource.GetAttribute("access_policy").AsStringValueOrDefault("", resource),
			})
		}
	}
	return vaults
}

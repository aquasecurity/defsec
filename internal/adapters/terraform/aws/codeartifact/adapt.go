package codeartifact

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codeartifact"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) codeartifact.Codeartifact {
	return codeartifact.Codeartifact{
		Domains: adaptDomains(modules),
	}
}

func adaptDomains(modules terraform.Modules) []codeartifact.Domain {
	var domains []codeartifact.Domain
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_codeartifact_domain") {
			domains = append(domains, codeartifact.Domain{
				Metadata:      resource.GetMetadata(),
				Arn:           resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
				EncryptionKey: resource.GetAttribute("encryption_key").AsStringValueOrDefault("", resource),
			})
		}
	}
	return domains
}

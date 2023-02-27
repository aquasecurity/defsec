package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func adaptCertificate(modules terraform.Modules) []iam.ServerCertificate {
	var certificates []iam.ServerCertificate

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("") {
			certificates = append(certificates, iam.ServerCertificate{
				Metadata:   resource.GetMetadata(),
				Name:       resource.GetAttribute("name").AsStringValueOrDefault("", resource),
				Expiration: types.TimeUnresolvable(resource.GetMetadata()),
			})

		}
	}
	return certificates
}

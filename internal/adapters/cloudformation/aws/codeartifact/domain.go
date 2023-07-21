package codeartifact

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codeartifact"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getDomain(ctx parser.FileContext) []codeartifact.Domain {

	var domains []codeartifact.Domain

	resources := ctx.GetResourcesByType("AWS::CodeArtifact::Domain")

	for _, r := range resources {
		domains = append(domains, codeartifact.Domain{
			Metadata:      r.Metadata(),
			Arn:           r.GetStringProperty("Arn"),
			EncryptionKey: r.GetStringProperty("EncryptionKey"),
		})
	}

	return domains
}

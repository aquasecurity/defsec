package voiceid

import (
	voiceid "github.com/aquasecurity/defsec/pkg/providers/aws/voiceId"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getDomain(ctx parser.FileContext) []voiceid.Domain {

	resources := ctx.GetResourcesByType("AWS::VoiceID::Domain")
	var domains []voiceid.Domain
	for _, r := range resources {
		domains = append(domains, voiceid.Domain{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("ServerSideEncryptionConfiguration.KmsKeyId"),
		})
	}
	return domains
}

package wisdom

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/wisdom"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getAssistant(ctx parser.FileContext) []wisdom.Assistant {

	resources := ctx.GetResourcesByType("AWS::Wisdom::Assistant")
	var assistants []wisdom.Assistant
	for _, r := range resources {
		assistants = append(assistants, wisdom.Assistant{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("ServerSideEncryptionConfiguration.KmsKeyId"),
		})
	}
	return assistants
}

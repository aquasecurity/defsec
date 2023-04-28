package apprunner

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/apprunner"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getListService(ctx parser.FileContext) (servicearn []apprunner.ListService) {

	ListService := ctx.GetResourcesByType("AWS::AppRunner::Service")

	for _, r := range ListService {
		var kmsKey defsecTypes.StringValue

		for range r.GetProperty("EncryptionConfiguration").Type() {
			kmsKey = r.GetStringProperty("KmsKey")
		}

		fd := apprunner.ListService{
			Metadata:   r.Metadata(),
			ServiceArn: r.GetStringProperty("ServiceArn"),
			KmsKey:     kmsKey,
		}
		servicearn = append(servicearn, fd)
	}

	return servicearn
}

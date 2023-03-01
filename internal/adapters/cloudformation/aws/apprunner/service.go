package apprunner

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/apprunner"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListService(ctx parser.FileContext) (servicearn []apprunner.ListService) {

	ListService := ctx.GetResourcesByType("AWS::AppRunner::Service")

	for _, r := range ListService {

		fd := apprunner.ListService{
			Metadata:   r.Metadata(),
			ServiceArn: r.GetStringProperty("ServiceArn"),
		}
		servicearn = append(servicearn, fd)
	}

	return servicearn
}

func getDescribeService(ctx parser.FileContext) (kmskey apprunner.DescribeService) {

	DescribeService := ctx.GetResourcesByType("AWS::AppRunner::Service")

	for _, r := range DescribeService {

		var KmsKey apprunner.DescribeService
		for range r.GetProperty("EncryptionConfiguration").AsString() {
			KmsKey = apprunner.DescribeService{
				Metadata: r.Metadata(),
				KmsKey:   r.GetStringProperty("KmsKey"),
			}
		}

		kk := KmsKey
		kmskey = kk
	}

	return kmskey
}

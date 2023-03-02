package mwaa

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/mwaa"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getEnvironments(ctx parser.FileContext) []mwaa.Environmnet {
	var environments []mwaa.Environmnet
	for _, r := range ctx.GetResourcesByType("AWS::MWAA::Environment") {
		environments = append(environments, mwaa.Environmnet{
			Metadata:            r.Metadata(),
			ExecutionRoleArn:    r.GetStringProperty("ExecutionRoleArn"),
			KmsKey:              r.GetStringProperty("KmsKey"),
			WebserverAccessMode: r.GetStringProperty("WebserverAccessMode"),
		})
	}
	return environments
}

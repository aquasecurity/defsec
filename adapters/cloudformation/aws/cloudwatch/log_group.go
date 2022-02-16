package cloudwatch

import (
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

func getLogGroups(ctx parser.FileContext) (logGroups []cloudwatch.LogGroup) {

	logGroupResources := ctx.GetResourceByType("AWS::Logs::LogGroup")

	for _, r := range logGroupResources {
		group := cloudwatch.LogGroup{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("LogGroupName"),
			KMSKeyID: r.GetStringProperty("KmsKeyId"),
		}
		logGroups = append(logGroups, group)
	}

	return logGroups
}

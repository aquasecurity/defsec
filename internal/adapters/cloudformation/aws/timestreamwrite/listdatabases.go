package timestreamwrite

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/timestreamwrite"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListDatabases(ctx parser.FileContext) (databasesInfo []timestreamwrite.Databases) {

	serverResources := ctx.GetResourcesByType("AWS::Timestream::Database")

	for _, r := range serverResources {
		databaseInfo := timestreamwrite.Databases{
			Metadata: r.Metadata(),
			Arn:      r.GetStringProperty("Arn"),
			KmsKeyID: r.GetStringProperty("KmsKeyId"),
		}

		databasesInfo = append(databasesInfo, databaseInfo)
	}

	return databasesInfo
}

package neptune

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/neptune"
	"github.com/aquasecurity/defsec/types"
)

func getClusters(ctx parser.FileContext) (clusters []neptune.Cluster) {
	for _, r := range ctx.GetResourceByType("AWS::Neptune::DBCluster") {

		cluster := neptune.Cluster{
			Metadata:          r.Metadata(),
			Logging: neptune.Logging{
				Audit: getAuditLog(r),
			},
			StorageEncrypted: r.GetBoolProperty("StorageEncrypted"),
			KMSKeyID:         r.GetStringProperty("KmsKeyId"),
		}
		clusters = append(clusters, cluster)
	}
	return clusters
}

func getAuditLog(r *parser.Resource) types.BoolValue {
	if logsProp := r.GetProperty("EnableCloudwatchLogsExports"); logsProp.IsList() {
		if logsProp.Contains("audit") {
			return types.Bool(true, logsProp.Metadata())
		}
	}

	return types.BoolDefault(false, r.Metadata())
}

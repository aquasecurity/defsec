package documentdb

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/documentdb"
)

func getClusters(ctx parser.FileContext) (clusters []documentdb.Cluster) {

	clusterResources := ctx.GetResourceByType("AWS::DocDB::DBCluster")

	for _, r := range clusterResources {
		cluster := documentdb.Cluster{
			Metadata:          r.Metadata(),
			Identifier:        r.GetStringProperty("DBClusterIdentifier"),
			EnabledLogExports: getLogExports(r),
			StorageEncrypted:  r.GetBoolProperty("StorageEncrypted"),
			KMSKeyID:          r.GetStringProperty("KmsKeyId"),
		}

		updateInstancesOnCluster(&cluster, ctx)

		clusters = append(clusters, cluster)
	}
	return clusters
}

func updateInstancesOnCluster(cluster *documentdb.Cluster, ctx parser.FileContext) {

	instanceResources := ctx.GetResourceByType("AWS::DocDB::DBInstance")

	for _, r := range instanceResources {
		clusterIdentifier := r.GetStringProperty("DBClusterIdentifier")
		if clusterIdentifier == cluster.Identifier {
			cluster.Instances = append(cluster.Instances, documentdb.Instance{
				Metadata: r.Metadata(),
				KMSKeyID: cluster.KMSKeyID,
			})
		}
	}
}

func getLogExports(r *parser.Resource) (logExports []types.StringValue) {

	exportsList := r.GetProperty("EnableCloudwatchLogsExports")

	if exportsList.IsNil() || exportsList.IsNotList() {
		return logExports
	}

	for _, export := range exportsList.AsList() {
		logExports = append(logExports, export.AsStringValue())
	}
	return logExports
}

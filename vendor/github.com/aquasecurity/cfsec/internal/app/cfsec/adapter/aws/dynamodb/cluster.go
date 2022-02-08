package dynamodb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
)

func getClusters(file parser.FileContext) (clusters []dynamodb.DAXCluster) {

	clusterResources := file.GetResourceByType("AWS::DAX::Cluster")

	for _, r := range clusterResources {
		cluster := dynamodb.DAXCluster{
			Metadata: r.Metadata(),
			ServerSideEncryption: dynamodb.ServerSideEncryption{
				Enabled: r.GetBoolProperty("SSESpecification.SSEEnabled"),
			},
			PointInTimeRecovery: nil,
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}

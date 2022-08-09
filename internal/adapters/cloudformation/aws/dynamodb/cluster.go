package dynamodb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

func getClusters(file parser.FileContext) (clusters []dynamodb.DAXCluster) {

	clusterResources := file.GetResourcesByType("AWS::DAX::Cluster")

	for _, r := range clusterResources {
		cluster := dynamodb.DAXCluster{
			Metadata: r.Metadata(),
			ServerSideEncryption: dynamodb.ServerSideEncryption{
				Metadata: r.Metadata(),
				Enabled:  types2.BoolDefault(false, r.Metadata()),
				KMSKeyID: types2.StringDefault("", r.Metadata()),
			},
			PointInTimeRecovery: types2.BoolUnresolvable(r.Metadata()),
		}

		if sseProp := r.GetProperty("SSESpecification"); sseProp.IsNotNil() {
			cluster.ServerSideEncryption = dynamodb.ServerSideEncryption{
				Metadata: sseProp.Metadata(),
				Enabled:  r.GetBoolProperty("SSESpecification.SSEEnabled"),
				KMSKeyID: types2.StringUnresolvable(sseProp.Metadata()),
			}
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}

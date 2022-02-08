package redshift

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/redshift"
)

func getClusters(ctx parser.FileContext) (clusters []redshift.Cluster) {
	for _, r := range ctx.GetResourceByType("AWS::Redshift::Cluster") {

		cluster := redshift.Cluster{
			Metadata:          r.Metadata(),
			Encryption: redshift.Encryption{
				Enabled:  r.GetBoolProperty("Encrypted"),
				KMSKeyID: r.GetStringProperty("KmsKeyId"),
			},
			SubnetGroupName: r.GetStringProperty("ClusterSubnetGroupName", ""),
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

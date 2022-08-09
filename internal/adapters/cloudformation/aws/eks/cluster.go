package eks

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

func getClusters(ctx parser.FileContext) (clusters []eks.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::EKS::Cluster")

	for _, r := range clusterResources {
		cluster := eks.Cluster{
			Metadata: r.Metadata(),
			// Logging not supported for cloudformation https://github.com/aws/containers-roadmap/issues/242
			Logging: eks.Logging{
				Metadata:          r.Metadata(),
				API:               types2.BoolUnresolvable(r.Metadata()),
				Audit:             types2.BoolUnresolvable(r.Metadata()),
				Authenticator:     types2.BoolUnresolvable(r.Metadata()),
				ControllerManager: types2.BoolUnresolvable(r.Metadata()),
				Scheduler:         types2.BoolUnresolvable(r.Metadata()),
			},
			Encryption: getEncryptionConfig(r),
			// endpoint protection not supported - https://github.com/aws/containers-roadmap/issues/242
			PublicAccessEnabled: types2.BoolUnresolvable(r.Metadata()),
			PublicAccessCIDRs:   nil,
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

func getEncryptionConfig(r *parser.Resource) eks.Encryption {

	encryption := eks.Encryption{
		Metadata: r.Metadata(),
		Secrets:  types2.BoolDefault(false, r.Metadata()),
		KMSKeyID: types2.StringDefault("", r.Metadata()),
	}

	if encProp := r.GetProperty("EncryptionConfig"); encProp.IsNotNil() {
		encryption.Metadata = encProp.Metadata()
		encryption.KMSKeyID = encProp.GetStringProperty("Provider.KeyArn")
		resourcesProp := encProp.GetProperty("Resources")
		if resourcesProp.IsList() {
			if resourcesProp.Contains("secrets") {
				encryption.Secrets = types2.Bool(true, resourcesProp.Metadata())
			}
		}
	}

	return encryption
}

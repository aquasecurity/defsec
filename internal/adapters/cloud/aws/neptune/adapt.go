package neptune

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/neptune/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "neptune"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Neptune.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getClusters() ([]neptune.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var apiClusters []types.DBCluster
	var input api.DescribeDBClustersInput
	for {
		output, err := a.api.DescribeDBClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.DBClusters...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")

	var clusters []neptune.Cluster
	for _, apiCluster := range apiClusters {
		cluster, err := a.adaptCluster(apiCluster)
		if err != nil {
			a.Debug("Failed to adapt cluster '%s': %s", *apiCluster.DBClusterArn, err)
			continue
		}
		clusters = append(clusters, *cluster)
		a.Tracker().IncrementResource()
	}

	return clusters, nil
}

func (a *adapter) adaptCluster(apiCluster types.DBCluster) (*neptune.Cluster, error) {

	metadata := a.CreateMetadataFromARN(*apiCluster.DBClusterArn)

	var kmsKeyId string
	if apiCluster.KmsKeyId != nil {
		kmsKeyId = *apiCluster.KmsKeyId
	}

	var auditLogging bool
	for _, export := range apiCluster.EnabledCloudwatchLogsExports {
		if export == "audit" {
			auditLogging = true
			break
		}
	}

	return &neptune.Cluster{
		Metadata: metadata,
		Logging: neptune.Logging{
			Metadata: metadata,
			Audit:    defsecTypes.Bool(auditLogging, metadata),
		},
		StorageEncrypted: defsecTypes.Bool(apiCluster.StorageEncrypted, metadata),
		KMSKeyID:         defsecTypes.String(kmsKeyId, metadata),
	}, nil
}

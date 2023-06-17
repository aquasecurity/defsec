package memorydb

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/memorydb"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/memorydb"
	"github.com/aws/aws-sdk-go-v2/service/memorydb/types"
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
	return "memorydb"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.MemoryDb.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getClusters() ([]memorydb.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var apiClusters []types.Cluster
	var input api.DescribeClustersInput

	for {
		output, err := a.api.DescribeClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apiClusters = append(apiClusters, output.Clusters...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting cluster...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(cluster types.Cluster) (*memorydb.Cluster, error) {
	metadata := a.CreateMetadataFromARN(*cluster.ARN)

	return &memorydb.Cluster{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(*cluster.KmsKeyId, metadata),
	}, nil
}

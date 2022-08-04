package elasticache

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticache/types"
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
	return "elasticache"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ElastiCache.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	state.AWS.ElastiCache.ReplicationGroups, err = a.getReplicationGroups()
	if err != nil {
		return err
	}

	// this can error if classic resources are requested where not available
	state.AWS.ElastiCache.SecurityGroups, _ = a.getSecurityGroups()

	return nil
}

func (a *adapter) getClusters() ([]elasticache.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var input api.DescribeCacheClustersInput
	var apiClusters []types.CacheCluster
	for {
		output, err := a.api.DescribeCacheClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.CacheClusters...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")

	var clusters []elasticache.Cluster
	for _, apiCluster := range apiClusters {
		cluster, err := a.adaptCluster(apiCluster)
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, *cluster)
		a.Tracker().IncrementResource()
	}

	return clusters, nil
}

func (a *adapter) adaptCluster(apiCluster types.CacheCluster) (*elasticache.Cluster, error) {
	metadata := a.CreateMetadataFromARN(*apiCluster.ARN)
	return &elasticache.Cluster{
		Metadata:               metadata,
		Engine:                 defsecTypes.String(*apiCluster.Engine, metadata),
		NodeType:               defsecTypes.String(*apiCluster.CacheNodeType, metadata),
		SnapshotRetentionLimit: defsecTypes.Int(int(*apiCluster.SnapshotRetentionLimit), metadata),
	}, nil
}

func (a *adapter) getReplicationGroups() ([]elasticache.ReplicationGroup, error) {

	a.Tracker().SetServiceLabel("Discovering replication groups...")

	var input api.DescribeReplicationGroupsInput
	var apiGroups []types.ReplicationGroup
	for {
		output, err := a.api.DescribeReplicationGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiGroups = append(apiGroups, output.ReplicationGroups...)
		a.Tracker().SetTotalResources(len(apiGroups))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting replication groups...")

	var groups []elasticache.ReplicationGroup
	for _, apiGroup := range apiGroups {
		group, err := a.adaptReplicationGroup(apiGroup)
		if err != nil {
			return nil, err
		}
		groups = append(groups, *group)
		a.Tracker().IncrementResource()
	}

	return groups, nil
}

func (a *adapter) adaptReplicationGroup(apiGroup types.ReplicationGroup) (*elasticache.ReplicationGroup, error) {
	metadata := a.CreateMetadataFromARN(*apiGroup.ARN)
	return &elasticache.ReplicationGroup{
		Metadata:                 metadata,
		TransitEncryptionEnabled: defsecTypes.Bool(*apiGroup.TransitEncryptionEnabled, metadata),
		AtRestEncryptionEnabled:  defsecTypes.Bool(*apiGroup.AtRestEncryptionEnabled, metadata),
	}, nil
}

func (a *adapter) getSecurityGroups() ([]elasticache.SecurityGroup, error) {

	a.Tracker().SetServiceLabel("Discovering security groups...")

	var input api.DescribeCacheSecurityGroupsInput
	var apiGroups []types.CacheSecurityGroup
	for {
		output, err := a.api.DescribeCacheSecurityGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiGroups = append(apiGroups, output.CacheSecurityGroups...)
		a.Tracker().SetTotalResources(len(apiGroups))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting security groups...")

	var groups []elasticache.SecurityGroup
	for _, apiGroup := range apiGroups {
		group, err := a.adaptSecurityGroup(apiGroup)
		if err != nil {
			return nil, err
		}
		groups = append(groups, *group)
		a.Tracker().IncrementResource()
	}

	return groups, nil
}

func (a *adapter) adaptSecurityGroup(apiGroup types.CacheSecurityGroup) (*elasticache.SecurityGroup, error) {
	metadata := a.CreateMetadataFromARN(*apiGroup.ARN)
	return &elasticache.SecurityGroup{
		Metadata:    metadata,
		Description: defsecTypes.String(*apiGroup.Description, metadata),
	}, nil
}

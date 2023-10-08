package elasticache

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticache"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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

	state.AWS.ElastiCache.ReservedCacheNodes, err = a.getCacheNodes()
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
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(apiCluster types.CacheCluster) (*elasticache.Cluster, error) {
	metadata := a.CreateMetadataFromARN(*apiCluster.ARN)

	engine := defsecTypes.StringDefault("", metadata)
	if apiCluster.Engine != nil {
		engine = defsecTypes.String(*apiCluster.Engine, metadata)
	}

	nodeType := defsecTypes.StringDefault("", metadata)
	if apiCluster.CacheNodeType != nil {
		nodeType = defsecTypes.String(*apiCluster.CacheNodeType, metadata)
	}

	limit := defsecTypes.IntDefault(0, metadata)
	if apiCluster.SnapshotRetentionLimit != nil {
		limit = defsecTypes.Int(int(*apiCluster.SnapshotRetentionLimit), metadata)
	}

	var port int
	if apiCluster.ConfigurationEndpoint != nil {
		port = int(apiCluster.ConfigurationEndpoint.Port)
	}

	return &elasticache.Cluster{
		Metadata:                 metadata,
		Id:                       defsecTypes.String(*apiCluster.CacheClusterId, metadata),
		EngineVersion:            defsecTypes.String(*apiCluster.EngineVersion, metadata),
		NumCacheNodes:            defsecTypes.Int(int(*apiCluster.NumCacheNodes), metadata),
		AtRestEncryptionEnabled:  defsecTypes.Bool(*apiCluster.AtRestEncryptionEnabled, metadata),
		TransitEncryptionEnabled: defsecTypes.Bool(*apiCluster.TransitEncryptionEnabled, metadata),
		CacheSubnetGroupName:     defsecTypes.String(*apiCluster.CacheSubnetGroupName, metadata),
		ConfigurationEndpoint: elasticache.ConfigurationEndpoint{
			Metadata: metadata,
			Port:     defsecTypes.Int(port, metadata),
		},
		Engine:                 engine,
		NodeType:               nodeType,
		SnapshotRetentionLimit: limit,
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
			a.Debug("Failed to adapt replication group '%s': %s", *apiGroup.ARN, err)
			continue
		}
		groups = append(groups, *group)
		a.Tracker().IncrementResource()
	}

	return groups, nil
}

func (a *adapter) adaptReplicationGroup(apiGroup types.ReplicationGroup) (*elasticache.ReplicationGroup, error) {
	metadata := a.CreateMetadataFromARN(*apiGroup.ARN)

	transitEncrypted := defsecTypes.BoolDefault(false, metadata)
	if apiGroup.TransitEncryptionEnabled != nil {
		transitEncrypted = defsecTypes.Bool(*apiGroup.TransitEncryptionEnabled, metadata)
	}
	atRestEncrypted := defsecTypes.BoolDefault(false, metadata)
	if apiGroup.AtRestEncryptionEnabled != nil {
		atRestEncrypted = defsecTypes.Bool(*apiGroup.AtRestEncryptionEnabled, metadata)
	}

	multiAZ := defsecTypes.BoolDefault(false, metadata)
	if apiGroup.MultiAZ == types.MultiAZStatusEnabled {
		multiAZ = defsecTypes.Bool(true, metadata)
	}

	return &elasticache.ReplicationGroup{
		Metadata:                 metadata,
		MultiAZ:                  multiAZ,
		KmsKeyId:                 defsecTypes.String(*apiGroup.KmsKeyId, metadata),
		TransitEncryptionEnabled: transitEncrypted,
		AtRestEncryptionEnabled:  atRestEncrypted,
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
			a.Debug("Failed to adapt security group '%s': %s", *apiGroup.ARN, err)
			continue
		}
		groups = append(groups, *group)
		a.Tracker().IncrementResource()
	}

	return groups, nil
}

func (a *adapter) adaptSecurityGroup(apiGroup types.CacheSecurityGroup) (*elasticache.SecurityGroup, error) {
	metadata := a.CreateMetadataFromARN(*apiGroup.ARN)
	description := defsecTypes.StringDefault("", metadata)
	if apiGroup.Description != nil {
		description = defsecTypes.String(*apiGroup.Description, metadata)
	}
	return &elasticache.SecurityGroup{
		Metadata:    metadata,
		Description: description,
	}, nil
}

func (a *adapter) getCacheNodes() ([]elasticache.ReservedCacheNode, error) {

	a.Tracker().SetServiceLabel("Discovering reserved cache nodes...")

	var input api.DescribeReservedCacheNodesInput
	var apiClusters []types.ReservedCacheNode
	for {
		output, err := a.api.DescribeReservedCacheNodes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.ReservedCacheNodes...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCacheNodes), nil
}

func (a *adapter) adaptCacheNodes(apiNodes types.ReservedCacheNode) (*elasticache.ReservedCacheNode, error) {

	metadata := a.CreateMetadataFromARN(*apiNodes.ReservationARN)

	return &elasticache.ReservedCacheNode{
		Metadata:  metadata,
		StartTime: defsecTypes.Time(*apiNodes.StartTime, metadata),
		Duration:  defsecTypes.Int(int(apiNodes.Duration), metadata),
		State:     defsecTypes.String(*apiNodes.State, metadata),
		NodeType:  defsecTypes.String(*apiNodes.CacheNodeType, metadata),
	}, nil
}

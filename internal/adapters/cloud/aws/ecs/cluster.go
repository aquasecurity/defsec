package ecs

import (
	"fmt"

	defsecTypes "github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"
	ecsapi "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func (a *adapter) getClusters() ([]ecs.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var clusterARNs []string

	var input ecsapi.ListClustersInput

	for {
		output, err := a.api.ListClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		clusterARNs = append(clusterARNs, output.ClusterArns...)
		a.Tracker().SetTotalResources(len(clusterARNs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	var clusters []ecs.Cluster

	for _, clusterARN := range clusterARNs {
		cluster, err := a.adaptCluster(clusterARN)
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, *cluster)
		a.Tracker().IncrementResource()
	}

	return clusters, nil
}

func (a *adapter) adaptCluster(arn string) (*ecs.Cluster, error) {

	metadata := a.CreateMetadataFromARN(arn)

	var enableInsights bool

	output, err := a.api.DescribeClusters(a.Context(), &ecsapi.DescribeClustersInput{
		Clusters: []string{arn},
		Include: []types.ClusterField{
			types.ClusterFieldSettings,
		},
	})
	if err != nil {
		return nil, err
	}
	if len(output.Clusters) == 0 {
		return nil, fmt.Errorf("cluster not found")
	}

	for _, setting := range output.Clusters[0].Settings {
		if setting.Name == types.ClusterSettingNameContainerInsights {
			enableInsights = setting.Value != nil && *setting.Value == "enabled"
		}
	}

	return &ecs.Cluster{
		Metadata: metadata,
		Settings: ecs.ClusterSettings{
			Metadata:                 metadata,
			ContainerInsightsEnabled: defsecTypes.Bool(enableInsights, metadata),
		},
	}, nil
}

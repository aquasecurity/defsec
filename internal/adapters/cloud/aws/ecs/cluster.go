package ecs

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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
	return concurrency.Adapt(clusterARNs, a.RootAdapter, a.adaptCluster), nil
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

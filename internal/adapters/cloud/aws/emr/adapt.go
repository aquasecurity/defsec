package emr

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/emr/types"
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
	return "emr"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.EMR.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	state.AWS.EMR.SecurityConfiguration, err = a.getSecurityConfigurations()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getClusters() ([]emr.Cluster, error) {

	a.Tracker().SetServiceLabel("Discovering clusters...")

	var apiClusters []types.ClusterSummary
	var input api.ListClustersInput
	for {
		output, err := a.api.ListClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.Clusters...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(apiCluster types.ClusterSummary) (*emr.Cluster, error) {

	metadata := a.CreateMetadataFromARN(*apiCluster.ClusterArn)

	output, err := a.api.DescribeCluster(a.Context(), &api.DescribeClusterInput{
		ClusterId: apiCluster.Id,
	})
	if err != nil {
		return nil, err
	}

	return &emr.Cluster{
		Metadata: metadata,
		Settings: emr.ClusterSettings{
			Metadata:     metadata,
			Name:         defsecTypes.String(*apiCluster.Name, metadata),
			ReleaseLabel: defsecTypes.String(*output.Cluster.ReleaseLabel, metadata),
			ServiceRole:  defsecTypes.String(*output.Cluster.ServiceRole, metadata),
		},
	}, nil
}

func (a *adapter) getSecurityConfigurations() ([]emr.SecurityConfiguration, error) {
	a.Tracker().SetServiceLabel("Discovering security configurations...")

	var apiConfigs []types.SecurityConfigurationSummary
	var input api.ListSecurityConfigurationsInput
	for {
		output, err := a.api.ListSecurityConfigurations(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiConfigs = append(apiConfigs, output.SecurityConfigurations...)
		a.Tracker().SetTotalResources(len(apiConfigs))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting security configurations...")

	var configs []emr.SecurityConfiguration
	for _, apiConfig := range apiConfigs {
		config, err := a.adaptConfig(apiConfig)
		if err != nil {
			a.Debug("Failed to adapt security configuration '%s': %s", *apiConfig.Name, err)
			continue
		}
		configs = append(configs, *config)
		a.Tracker().IncrementResource()
	}

	return configs, nil
}

func (a *adapter) adaptConfig(config types.SecurityConfigurationSummary) (*emr.SecurityConfiguration, error) {

	metadata := a.CreateMetadata("config/" + *config.Name)

	output, err := a.api.DescribeSecurityConfiguration(a.Context(), &api.DescribeSecurityConfigurationInput{
		Name: config.Name,
	})
	if err != nil {
		return nil, err
	}

	return &emr.SecurityConfiguration{
		Metadata:      metadata,
		Name:          defsecTypes.String(*config.Name, metadata),
		Configuration: defsecTypes.String(*output.SecurityConfiguration, metadata),
	}, nil
}

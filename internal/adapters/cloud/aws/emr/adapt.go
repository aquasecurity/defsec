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

	var masterinstance emr.Instance
	var coreinstance emr.Instance
	group, err := a.api.ListInstanceGroups(a.Context(), &api.ListInstanceGroupsInput{
		ClusterId: apiCluster.Id,
	})
	if err != nil {
		for _, g := range group.InstanceGroups {

			masterinstancetype := defsecTypes.StringDefault("", metadata)
			masterinstancecount := defsecTypes.IntDefault(1, metadata)
			if g.InstanceGroupType == types.InstanceGroupTypeMaster {
				masterinstancetype = defsecTypes.String(*g.InstanceType, metadata)
				masterinstancecount = defsecTypes.Int(int(*g.RunningInstanceCount), metadata)
			}
			masterinstance = emr.Instance{
				Metadata:      metadata,
				InstanceType:  masterinstancetype,
				InstanceCount: masterinstancecount,
			}
			coreinstancetype := defsecTypes.StringDefault("", metadata)
			coreinstancecount := defsecTypes.IntDefault(1, metadata)
			if g.InstanceGroupType == types.InstanceGroupTypeCore {
				coreinstancetype = defsecTypes.String(*g.InstanceType, metadata)
				coreinstancecount = defsecTypes.Int(int(*g.RunningInstanceCount), metadata)
			}
			coreinstance = emr.Instance{
				Metadata:      metadata,
				InstanceType:  coreinstancetype,
				InstanceCount: coreinstancecount,
			}
		}
	}

	name := defsecTypes.StringDefault("", metadata)
	if apiCluster.Name != nil {
		name = defsecTypes.String(*apiCluster.Name, metadata)
	}

	releaseLabel := defsecTypes.StringDefault("", metadata)
	if output.Cluster != nil && output.Cluster.ReleaseLabel != nil {
		releaseLabel = defsecTypes.String(*output.Cluster.ReleaseLabel, metadata)
	}

	serviceRole := defsecTypes.StringDefault("", metadata)
	if output.Cluster != nil && output.Cluster.ServiceRole != nil {
		serviceRole = defsecTypes.String(*output.Cluster.ServiceRole, metadata)
	}

	var ec2SubnetId string
	if output.Cluster.Ec2InstanceAttributes != nil {
		ec2SubnetId = *output.Cluster.Ec2InstanceAttributes.Ec2SubnetId
	}

	return &emr.Cluster{
		Metadata:    metadata,
		EC2SubnetId: defsecTypes.String(ec2SubnetId, metadata),
		LogUri:      defsecTypes.String(*output.Cluster.LogUri, metadata),
		Settings: emr.ClusterSettings{
			Metadata:     metadata,
			Name:         name,
			ReleaseLabel: releaseLabel,
			ServiceRole:  serviceRole,
		},
		InstanceGroup: emr.InstanceGroup{
			Metadata:            metadata,
			CoreInstanceGroup:   coreinstance,
			MasterInstanceGroup: masterinstance,
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

	name := defsecTypes.StringDefault("", metadata)
	if config.Name != nil {
		name = defsecTypes.String(*config.Name, metadata)
	}

	secConf := defsecTypes.StringDefault("", metadata)
	if output.SecurityConfiguration != nil {
		secConf = defsecTypes.String(*output.SecurityConfiguration, metadata)
	}

	return &emr.SecurityConfiguration{
		Metadata:      metadata,
		Name:          name,
		Configuration: secConf,
	}, nil
}

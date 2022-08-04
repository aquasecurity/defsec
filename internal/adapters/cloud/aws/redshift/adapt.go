package redshift

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshift/types"
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
	return "redshift"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Redshift.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	// this can error is classic resources are used where disabled
	state.AWS.Redshift.SecurityGroups, _ = a.getSecurityGroups()

	return nil
}

func (a *adapter) getClusters() ([]redshift.Cluster, error) {

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
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting clusters...")

	var clusters []redshift.Cluster
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

func (a *adapter) adaptCluster(apiCluster types.Cluster) (*redshift.Cluster, error) {

	metadata := a.CreateMetadataFromARN(*apiCluster.ClusterNamespaceArn)

	var kmsKeyId string
	if apiCluster.KmsKeyId != nil {
		kmsKeyId = *apiCluster.KmsKeyId
	}

	var subnetGroupName string
	if apiCluster.ClusterSubnetGroupName != nil {
		subnetGroupName = *apiCluster.ClusterSubnetGroupName
	}

	return &redshift.Cluster{
		Metadata: metadata,
		Encryption: redshift.Encryption{
			Metadata: metadata,
			Enabled:  defsecTypes.Bool(apiCluster.Encrypted, metadata),
			KMSKeyID: defsecTypes.String(kmsKeyId, metadata),
		},
		SubnetGroupName: defsecTypes.String(subnetGroupName, metadata),
	}, nil
}

func (a *adapter) getSecurityGroups() ([]redshift.SecurityGroup, error) {

	a.Tracker().SetServiceLabel("Discovering security groups...")

	var apiGroups []types.ClusterSecurityGroup
	var input api.DescribeClusterSecurityGroupsInput
	for {
		output, err := a.api.DescribeClusterSecurityGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiGroups = append(apiGroups, output.ClusterSecurityGroups...)
		a.Tracker().SetTotalResources(len(apiGroups))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting security groups...")

	var securityGroups []redshift.SecurityGroup
	for _, apiGroup := range apiGroups {
		group, err := a.adaptSecurityGroup(apiGroup)
		if err != nil {
			return nil, err
		}
		securityGroups = append(securityGroups, *group)
		a.Tracker().IncrementResource()
	}

	return securityGroups, nil
}

func (a *adapter) adaptSecurityGroup(apiSG types.ClusterSecurityGroup) (*redshift.SecurityGroup, error) {

	metadata := a.CreateMetadata("securitygroup:" + *apiSG.ClusterSecurityGroupName)

	return &redshift.SecurityGroup{
		Metadata:    metadata,
		Description: defsecTypes.String(*apiSG.Description, metadata),
	}, nil
}

package redshift

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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

	state.AWS.Redshift.ReservedNodes, err = a.getReservedNodes()
	if err != nil {
		return err
	}

	state.AWS.Redshift.ClusterParameters, err = a.getParameters()
	if err != nil {
		return err
	}

	// this can error is classic resources are used where disabled
	state.AWS.Redshift.SecurityGroups, err = a.getSecurityGroups()
	if err != nil {
		a.Debug("Failed to adapt security groups: %s", err)
		return nil
	}

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
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptCluster), nil
}

func (a *adapter) adaptCluster(apiCluster types.Cluster) (*redshift.Cluster, error) {

	metadata := a.CreateMetadataFromARN(*apiCluster.ClusterNamespaceArn)

	output, err := a.api.DescribeLoggingStatus(a.Context(), &api.DescribeLoggingStatusInput{
		ClusterIdentifier: apiCluster.ClusterIdentifier,
	})
	if err != nil {
		output = nil
	}

	var loggingenabled bool
	if output != nil {
		loggingenabled = output.LoggingEnabled
	}

	var kmsKeyId string
	if apiCluster.KmsKeyId != nil {
		kmsKeyId = *apiCluster.KmsKeyId
	}

	var subnetGroupName string
	if apiCluster.ClusterSubnetGroupName != nil {
		subnetGroupName = *apiCluster.ClusterSubnetGroupName
	}

	var port int
	if apiCluster.Endpoint != nil {
		port = int(apiCluster.Endpoint.Port)
	}

	return &redshift.Cluster{
		Metadata:                         metadata,
		ClusterIdentifier:                defsecTypes.String(*apiCluster.ClusterIdentifier, metadata),
		AllowVersionUpgrade:              defsecTypes.Bool(apiCluster.AllowVersionUpgrade, metadata),
		NumberOfNodes:                    defsecTypes.Int(int(apiCluster.NumberOfNodes), metadata),
		NodeType:                         defsecTypes.String(*apiCluster.NodeType, metadata),
		PubliclyAccessible:               defsecTypes.Bool(apiCluster.PubliclyAccessible, metadata),
		VpcId:                            defsecTypes.String(*apiCluster.VpcId, metadata),
		MasterUsername:                   defsecTypes.String(*apiCluster.MasterUsername, metadata),
		AutomatedSnapshotRetentionPeriod: defsecTypes.Int(int(apiCluster.ManualSnapshotRetentionPeriod), metadata),
		LoggingEnabled:                   defsecTypes.Bool(loggingenabled, metadata),
		EndPoint: redshift.EndPoint{
			Metadata: metadata,
			Port:     defsecTypes.Int(port, metadata),
		},
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
	return concurrency.Adapt(apiGroups, a.RootAdapter, a.adaptSecurityGroup), nil
}

func (a *adapter) adaptSecurityGroup(apiSG types.ClusterSecurityGroup) (*redshift.SecurityGroup, error) {

	metadata := a.CreateMetadata("securitygroup:" + *apiSG.ClusterSecurityGroupName)

	description := defsecTypes.StringDefault("", metadata)
	if apiSG.Description != nil {
		description = defsecTypes.String(*apiSG.Description, metadata)
	}

	return &redshift.SecurityGroup{
		Metadata:    metadata,
		Description: description,
	}, nil
}

func (a *adapter) getReservedNodes() ([]redshift.ReservedNode, error) {

	a.Tracker().SetServiceLabel("Discovering reserved nodes...")

	var apiReservednodes []types.ReservedNode
	var input api.DescribeReservedNodesInput
	for {
		output, err := a.api.DescribeReservedNodes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiReservednodes = append(apiReservednodes, output.ReservedNodes...)
		a.Tracker().SetTotalResources(len(apiReservednodes))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting reserved node ...")
	return concurrency.Adapt(apiReservednodes, a.RootAdapter, a.adaptnode), nil
}

func (a *adapter) adaptnode(node types.ReservedNode) (*redshift.ReservedNode, error) {
	metadata := a.CreateMetadata(*node.ReservedNodeId)
	return &redshift.ReservedNode{
		Metadata: metadata,
		NodeType: defsecTypes.String(*node.NodeType, metadata),
	}, nil
}

func (a *adapter) getParameters() ([]redshift.ClusterParameter, error) {

	a.Tracker().SetServiceLabel("Discovering cluster parameters group...")

	var apiClusters []types.ClusterParameterGroup
	var input api.DescribeClusterParameterGroupsInput
	for {
		output, err := a.api.DescribeClusterParameterGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiClusters = append(apiClusters, output.ParameterGroups...)
		a.Tracker().SetTotalResources(len(apiClusters))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting cluster parameters...")
	return concurrency.Adapt(apiClusters, a.RootAdapter, a.adaptParameter), nil
}

func (a *adapter) adaptParameter(parameter types.ClusterParameterGroup) (*redshift.ClusterParameter, error) {

	output, err := a.api.DescribeClusterParameters(a.Context(), &api.DescribeClusterParametersInput{
		ParameterGroupName: parameter.ParameterGroupName,
	})
	if err != nil {
		return nil, err
	}
	metadata := a.CreateMetadata(*parameter.ParameterGroupName)
	var clusterParameters redshift.ClusterParameter
	for _, P := range output.Parameters {
		clusterParameters = redshift.ClusterParameter{
			Metadata:       metadata,
			ParameterName:  defsecTypes.String(*P.ParameterName, metadata),
			ParameterValue: defsecTypes.String(*P.ParameterValue, metadata),
		}
	}
	return &clusterParameters, nil
}

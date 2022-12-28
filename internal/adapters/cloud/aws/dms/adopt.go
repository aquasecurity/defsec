package dms

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dms"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
)

type adapter struct {
	*aws.RootAdapter
	client *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "dms"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.DMS.ReplicationInstances, err = a.getReplicationInstances()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getReplicationInstances() ([]dms.ReplicationInstance, error) {

	a.Tracker().SetServiceLabel("Discovering replicationinststances...")

	var apiReplicationInstances []types.ReplicationInstance
	var input api.DescribeReplicationInstancesInput
	for {
		output, err := a.client.DescribeReplicationInstances(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiReplicationInstances = append(apiReplicationInstances, output.ReplicationInstances...)
		a.Tracker().SetTotalResources(len(apiReplicationInstances))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker
	}

	a.Tracker().SetServiceLabel("Adapting replicationinstances...")
	return concurrency.Adapt(apiReplicationInstances, a.RootAdapter, a.adaptReplicationIntsance), nil
}

func (a *adapter) adaptReplicationIntsance(ReplicationInstance types.ReplicationInstance) (*dms.ReplicationInstance, error) {
	metadata := a.CreateMetadataFromARN(*ReplicationInstance.ReplicationInstanceArn)

	return &dms.ReplicationInstance{
		Metadata:                metadata,
		AutoMinorVersionUpgrade: defsecTypes.Bool(ReplicationInstance.AutoMinorVersionUpgrade, metadata),
		MultiAZ:                 defsecTypes.Bool(ReplicationInstance.AutoMinorVersionUpgrade, metadata),
		PubliclyAccessible:      defsecTypes.Bool(ReplicationInstance.PubliclyAccessible, metadata),
	}, nil
}

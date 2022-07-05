package rds

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/state"
	rdsApi "github.com/aws/aws-sdk-go-v2/service/rds"
)

type adapter struct {
	*aws.RootAdapter
	api *rdsApi.Client
}

func (a adapter) Name() string {
	return "rds"
}

func (a adapter) Provider() string {
	return "aws"
}

func (a adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = rdsApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.RDS.Instances, err = a.getInstances()
	if err != nil {
		return err
	}

	state.AWS.RDS.Clusters, err = a.getClusters()
	if err != nil {
		return err
	}

	state.AWS.RDS.Classic, err = a.getClassic()
	if err != nil {
		return err
	}

	return nil
}

func (a adapter) getInstances() (instances []rds.Instance, err error) {

	return instances, nil
}

func (a adapter) getClusters() (clusters []rds.Cluster, err error) {

	return clusters, nil
}

func (a adapter) getClassic() (classic rds.Classic, err error) {

	return classic, nil
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

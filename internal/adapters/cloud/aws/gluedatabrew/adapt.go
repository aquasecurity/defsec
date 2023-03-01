package gluedatabrew

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/gluedatabrew"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/databrew"
	"github.com/aws/aws-sdk-go-v2/service/databrew/types"
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
	return "databrew"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.GlueDataBrew.Jobs, err = a.getJobs()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getJobs() ([]gluedatabrew.Job, error) {

	a.Tracker().SetServiceLabel("Discovering jobs...")

	var apijobs []types.Job
	var input api.ListJobsInput
	for {
		output, err := a.api.ListJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apijobs = append(apijobs, output.Jobs...)
		a.Tracker().SetTotalResources(len(apijobs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting jobs...")
	return concurrency.Adapt(apijobs, a.RootAdapter, a.adaptJob), nil
}

func (a *adapter) adaptJob(job types.Job) (*gluedatabrew.Job, error) {
	metadata := a.CreateMetadata(*job.AccountId)

	return &gluedatabrew.Job{
		Metadata:         metadata,
		EncryptionMode:   defsecTypes.String(string(job.EncryptionMode), metadata),
		EncryptionKeyArn: defsecTypes.String(*job.EncryptionKeyArn, metadata),
	}, nil
}

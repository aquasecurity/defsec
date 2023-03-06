package translate

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/translate"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/translate"
	aatypes "github.com/aws/aws-sdk-go-v2/service/translate/types"
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
	return "translate"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Translate.ListTextTranslateJobs, err = a.getListWebACLs()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getListWebACLs() ([]translate.ListJob, error) {

	a.Tracker().SetServiceLabel("Discovering list text translate jobs...")

	var apiListTextTranslateJobs []aatypes.TextTranslationJobProperties
	var input api.ListTextTranslationJobsInput
	for {
		output, err := a.api.ListTextTranslationJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListTextTranslateJobs = append(apiListTextTranslateJobs, output.TextTranslationJobPropertiesList...)
		a.Tracker().SetTotalResources(len(apiListTextTranslateJobs))
		if output.TextTranslationJobPropertiesList == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting list translation text jobs...")
	return concurrency.Adapt(apiListTextTranslateJobs, a.RootAdapter, a.adaptListWebACLs), nil
}

func (a *adapter) adaptListWebACLs(apiListTextTranslateJobs aatypes.TextTranslationJobProperties) (*translate.ListJob, error) {

	metadata := a.CreateMetadataFromARN(*apiListTextTranslateJobs.DataAccessRoleArn)

	var jobid string
	if apiListTextTranslateJobs.OutputDataConfig.EncryptionKey.Id != nil {
		jobid = *apiListTextTranslateJobs.OutputDataConfig.EncryptionKey.Id
	}

	var jobname string
	if apiListTextTranslateJobs.JobName != nil {
		jobname = *apiListTextTranslateJobs.JobName
	}

	return &translate.ListJob{
		Metadata:        metadata,
		JobName:         defsecTypes.String(jobname, metadata),
		EncryptionkeyId: defsecTypes.String(jobid, metadata),
	}, nil
}

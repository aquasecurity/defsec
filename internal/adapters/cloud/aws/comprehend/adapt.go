package comprehend

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/comprehend"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/comprehend"
	types "github.com/aws/aws-sdk-go-v2/service/comprehend/types"
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
	return "comprehend"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Comprehend.EntitiesDetectionJobs, err = a.getEDJobs()
	if err != nil {
		return err
	}

	state.AWS.Comprehend.DominantLanguageDetectionJobs, err = a.getDLDJobs()
	if err != nil {
		return err
	}

	state.AWS.Comprehend.TopicsDetectionJobs, err = a.getTDJobs()
	if err != nil {
		return err
	}

	state.AWS.Comprehend.SentimentDetectionJobs, err = a.getSDJobs()
	if err != nil {
		return err
	}

	state.AWS.Comprehend.KeyPhrasesDetectionJobs, err = a.getKPDJobs()
	if err != nil {
		return err
	}

	state.AWS.Comprehend.DocumentClassificationJobs, err = a.getDCJobs()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getEDJobs() ([]comprehend.EntitiesDetectionJob, error) {

	a.Tracker().SetServiceLabel("Discovering jobs...")

	var jobs []types.EntitiesDetectionJobProperties
	var input api.ListEntitiesDetectionJobsInput
	for {
		output, err := a.client.ListEntitiesDetectionJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, output.EntitiesDetectionJobPropertiesList...)
		a.Tracker().SetTotalResources(len(jobs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting jobs...")
	return concurrency.Adapt(jobs, a.RootAdapter, a.adaptEDjob), nil
}

func (a *adapter) adaptEDjob(job types.EntitiesDetectionJobProperties) (*comprehend.EntitiesDetectionJob, error) {
	metadata := a.CreateMetadataFromARN(*job.JobArn)

	return &comprehend.EntitiesDetectionJob{
		Metadata:       metadata,
		VolumeKmsKeyId: defsecTypes.String(*job.VolumeKmsKeyId, metadata),
		KmsKeyId:       defsecTypes.String(*job.OutputDataConfig.KmsKeyId, metadata),
	}, nil
}

func (a *adapter) getDLDJobs() ([]comprehend.DominantLanguageDetectionJob, error) {

	a.Tracker().SetServiceLabel("Discovering jobs...")

	var jobs []types.DominantLanguageDetectionJobProperties
	var input api.ListDominantLanguageDetectionJobsInput
	for {
		output, err := a.client.ListDominantLanguageDetectionJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, output.DominantLanguageDetectionJobPropertiesList...)
		a.Tracker().SetTotalResources(len(jobs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting jobs...")
	return concurrency.Adapt(jobs, a.RootAdapter, a.adaptDLDjob), nil
}

func (a *adapter) adaptDLDjob(job types.DominantLanguageDetectionJobProperties) (*comprehend.DominantLanguageDetectionJob, error) {
	metadata := a.CreateMetadataFromARN(*job.JobArn)

	return &comprehend.DominantLanguageDetectionJob{
		Metadata:       metadata,
		VolumeKmsKeyId: defsecTypes.String(*job.VolumeKmsKeyId, metadata),
		KmsKeyId:       defsecTypes.String(*job.OutputDataConfig.KmsKeyId, metadata),
	}, nil
}

func (a *adapter) getTDJobs() ([]comprehend.TopicsDetectionJob, error) {

	a.Tracker().SetServiceLabel("Discovering jobs...")

	var jobs []types.TopicsDetectionJobProperties
	var input api.ListTopicsDetectionJobsInput
	for {
		output, err := a.client.ListTopicsDetectionJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, output.TopicsDetectionJobPropertiesList...)
		a.Tracker().SetTotalResources(len(jobs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting jobs...")
	return concurrency.Adapt(jobs, a.RootAdapter, a.adaptTDjob), nil
}

func (a *adapter) adaptTDjob(job types.TopicsDetectionJobProperties) (*comprehend.TopicsDetectionJob, error) {
	metadata := a.CreateMetadataFromARN(*job.JobArn)

	return &comprehend.TopicsDetectionJob{
		Metadata:       metadata,
		VolumeKmsKeyId: defsecTypes.String(*job.VolumeKmsKeyId, metadata),
		KmsKeyId:       defsecTypes.String(*job.OutputDataConfig.KmsKeyId, metadata),
	}, nil
}

func (a *adapter) getSDJobs() ([]comprehend.SentimentDetectionJob, error) {

	a.Tracker().SetServiceLabel("Discovering jobs...")

	var jobs []types.SentimentDetectionJobProperties
	var input api.ListSentimentDetectionJobsInput
	for {
		output, err := a.client.ListSentimentDetectionJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, output.SentimentDetectionJobPropertiesList...)
		a.Tracker().SetTotalResources(len(jobs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting jobs...")
	return concurrency.Adapt(jobs, a.RootAdapter, a.adaptSDjob), nil
}

func (a *adapter) adaptSDjob(job types.SentimentDetectionJobProperties) (*comprehend.SentimentDetectionJob, error) {
	metadata := a.CreateMetadataFromARN(*job.JobArn)

	return &comprehend.SentimentDetectionJob{
		Metadata:       metadata,
		VolumeKmsKeyId: defsecTypes.String(*job.VolumeKmsKeyId, metadata),
		KmsKeyId:       defsecTypes.String(*job.OutputDataConfig.KmsKeyId, metadata),
	}, nil
}

func (a *adapter) getKPDJobs() ([]comprehend.KeyPhrasesDetectionJob, error) {

	a.Tracker().SetServiceLabel("Discovering jobs...")

	var jobs []types.KeyPhrasesDetectionJobProperties
	var input api.ListKeyPhrasesDetectionJobsInput
	for {
		output, err := a.client.ListKeyPhrasesDetectionJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, output.KeyPhrasesDetectionJobPropertiesList...)
		a.Tracker().SetTotalResources(len(jobs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting jobs...")
	return concurrency.Adapt(jobs, a.RootAdapter, a.adaptKPDjob), nil
}

func (a *adapter) adaptKPDjob(job types.KeyPhrasesDetectionJobProperties) (*comprehend.KeyPhrasesDetectionJob, error) {
	metadata := a.CreateMetadataFromARN(*job.JobArn)

	return &comprehend.KeyPhrasesDetectionJob{
		Metadata:       metadata,
		VolumeKmsKeyId: defsecTypes.String(*job.VolumeKmsKeyId, metadata),
		KmsKeyId:       defsecTypes.String(*job.OutputDataConfig.KmsKeyId, metadata),
	}, nil
}

func (a *adapter) getDCJobs() ([]comprehend.DocumentClassificationJob, error) {

	a.Tracker().SetServiceLabel("Discovering jobs...")

	var jobs []types.DocumentClassificationJobProperties
	var input api.ListDocumentClassificationJobsInput
	for {
		output, err := a.client.ListDocumentClassificationJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, output.DocumentClassificationJobPropertiesList...)
		a.Tracker().SetTotalResources(len(jobs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting jobs...")
	return concurrency.Adapt(jobs, a.RootAdapter, a.adaptDCjob), nil
}

func (a *adapter) adaptDCjob(job types.DocumentClassificationJobProperties) (*comprehend.DocumentClassificationJob, error) {
	metadata := a.CreateMetadataFromARN(*job.JobArn)

	return &comprehend.DocumentClassificationJob{
		Metadata:       metadata,
		VolumeKmsKeyId: defsecTypes.String(*job.VolumeKmsKeyId, metadata),
		KmsKeyId:       defsecTypes.String(*job.OutputDataConfig.KmsKeyId, metadata),
	}, nil
}

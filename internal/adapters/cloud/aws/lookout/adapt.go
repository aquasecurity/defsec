package lookout

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/lookout"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	equipmentapi "github.com/aws/aws-sdk-go-v2/service/lookoutequipment"
	equipmenttypes "github.com/aws/aws-sdk-go-v2/service/lookoutequipment/types"
	metricapi "github.com/aws/aws-sdk-go-v2/service/lookoutmetrics"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/lookoutmetrics/types"
	visionapi "github.com/aws/aws-sdk-go-v2/service/lookoutvision"
	visiontypes "github.com/aws/aws-sdk-go-v2/service/lookoutvision/types"
)

type adapter struct {
	*aws.RootAdapter
	metricapi    *metricapi.Client
	equipmentapi *equipmentapi.Client
	visionapi    *visionapi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "lookout"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.metricapi = metricapi.NewFromConfig(root.SessionConfig())
	a.equipmentapi = equipmentapi.NewFromConfig(root.SessionConfig())
	a.visionapi = visionapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Lookout.AnomalyDetectors, err = a.getDetectors()
	if err != nil {
		return err
	}

	state.AWS.Lookout.Datasets, err = a.getDatasets()
	if err != nil {
		return err
	}

	state.AWS.Lookout.Models, err = a.getModels()
	if err != nil {
		return nil
	}

	return nil
}

func (a *adapter) getDetectors() ([]lookout.AnomalyDetector, error) {

	a.Tracker().SetServiceLabel("Discovering anomaly Detectors...")

	var apidetectors []metrictypes.AnomalyDetectorSummary
	var input metricapi.ListAnomalyDetectorsInput
	for {
		output, err := a.metricapi.ListAnomalyDetectors(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apidetectors = append(apidetectors, output.AnomalyDetectorSummaryList...)
		a.Tracker().SetTotalResources(len(apidetectors))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting anomaly Detector...")
	return concurrency.Adapt(apidetectors, a.RootAdapter, a.adaptDetector), nil
}

func (a *adapter) adaptDetector(detector metrictypes.AnomalyDetectorSummary) (*lookout.AnomalyDetector, error) {
	metadata := a.CreateMetadataFromARN(*detector.AnomalyDetectorArn)

	output, err := a.metricapi.DescribeAnomalyDetector(a.Context(), &metricapi.DescribeAnomalyDetectorInput{
		AnomalyDetectorArn: detector.AnomalyDetectorArn,
	})
	if err != nil {
		return nil, err
	}

	return &lookout.AnomalyDetector{
		Metadata:  metadata,
		KmsKeyArn: defsecTypes.String(*output.KmsKeyArn, metadata),
	}, nil
}

func (a *adapter) getDatasets() ([]lookout.Dataset, error) {

	a.Tracker().SetServiceLabel("Discovering datasets...")

	var apidatasets []equipmenttypes.DatasetSummary
	var input equipmentapi.ListDatasetsInput
	for {
		output, err := a.equipmentapi.ListDatasets(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apidatasets = append(apidatasets, output.DatasetSummaries...)
		a.Tracker().SetTotalResources(len(apidatasets))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting dataset...")
	return concurrency.Adapt(apidatasets, a.RootAdapter, a.adaptDataset), nil
}

func (a *adapter) adaptDataset(dataset equipmenttypes.DatasetSummary) (*lookout.Dataset, error) {

	metadata := a.CreateMetadataFromARN(*dataset.DatasetArn)

	output, err := a.equipmentapi.DescribeDataset(a.Context(), &equipmentapi.DescribeDatasetInput{
		DatasetName: dataset.DatasetName,
	})
	if err != nil {
		return nil, err
	}

	return &lookout.Dataset{
		Metadata:           metadata,
		ServerSideKmsKeyId: defsecTypes.String(*output.ServerSideKmsKeyId, metadata),
	}, nil
}

func (a *adapter) getModels() ([]lookout.Model, error) {

	a.Tracker().SetServiceLabel("Discovering models...")

	var apimodels []visiontypes.ModelMetadata
	var input visionapi.ListProjectsInput
	output, err := a.visionapi.ListProjects(a.Context(), &input)
	if err != nil {
		return nil, err
	}
	for _, project := range output.Projects {
		model, err := a.visionapi.ListModels(a.Context(), &visionapi.ListModelsInput{
			ProjectName: project.ProjectName,
		})
		if err != nil {
			return nil, err
		}
		apimodels = append(apimodels, model.Models...)
		a.Tracker().SetTotalResources(len(apimodels))
		if model.NextToken == nil {
			break
		}
		input.NextToken = model.NextToken

	}

	a.Tracker().SetServiceLabel("Adapting model...")
	return concurrency.Adapt(apimodels, a.RootAdapter, a.adaptModel), nil
}

func (a *adapter) adaptModel(model visiontypes.ModelMetadata) (*lookout.Model, error) {

	metadata := a.CreateMetadataFromARN(*model.ModelArn)
	output, err := a.visionapi.DescribeModel(a.Context(), &visionapi.DescribeModelInput{
		ModelVersion: model.ModelVersion,
	})
	if err != nil {
		return nil, err
	}
	return &lookout.Model{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(*output.ModelDescription.KmsKeyId, metadata),
	}, nil
}

package forecast

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/forecast"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/forecast"
	aatypes "github.com/aws/aws-sdk-go-v2/service/forecast/types"
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
	return "forecast"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Forecast.ListForecastExportJobs, err = a.getForeCastExportJobs()
	if err != nil {
		return err
	}

	state.AWS.Forecast.ListDatasets, err = a.getListDatasets()
	if err != nil {
		return err
	}

	state.AWS.Forecast.DescribeDatasets, err = a.getDescribeDatasets()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getForeCastExportJobs() ([]forecast.ListForecastExportJob, error) {
	var apiListExportJobs []aatypes.ForecastExportJobSummary
	var input api.ListForecastExportJobsInput

	for {
		output, err := a.api.ListForecastExportJobs(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListExportJobs = append(apiListExportJobs, output.ForecastExportJobs...)

		a.Tracker().SetTotalResources(len(apiListExportJobs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}
	a.Tracker().SetServiceLabel("Adapting forecast...")
	return concurrency.Adapt(apiListExportJobs, a.RootAdapter, a.adaptListExportJobs), nil

}

func (a *adapter) getListDatasets() ([]forecast.ListDataset, error) {
	var apiListDatasets []aatypes.DatasetSummary
	var input api.ListDatasetsInput

	for {
		output, err := a.api.ListDatasets(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiListDatasets = append(apiListDatasets, output.Datasets...)

		a.Tracker().SetTotalResources(len(apiListDatasets))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}
	a.Tracker().SetServiceLabel("Adapting forecast...")
	return concurrency.Adapt(apiListDatasets, a.RootAdapter, a.adaptListDataset), nil

}

func (a *adapter) getDescribeDatasets() (forecast.DescribeDataset, error) {
	var apiDescribeDataset aatypes.EncryptionConfig
	var input api.DescribeDatasetInput

	metadata := a.CreateMetadataFromARN(*apiDescribeDataset.KMSKeyArn)

	var KEYARN string
	if apiDescribeDataset.KMSKeyArn != nil {
		KEYARN = *apiDescribeDataset.KMSKeyArn
	}

	describedataset := forecast.DescribeDataset{
		Metadata:  metadata,
		KMSKeyArn: types.String(KEYARN, metadata),
	}

	output, err := a.api.DescribeDataset(a.Context(), &input)
	if err != nil {
		return describedataset, err
	}
	apiDescribeDataset = *output.EncryptionConfig

	a.Tracker().SetServiceLabel("Adapting forecast...")
	return describedataset, nil

}

func (a *adapter) adaptListExportJobs(apiListExportJobs aatypes.ForecastExportJobSummary) (*forecast.ListForecastExportJob, error) {
	metadata := a.CreateMetadataFromARN(*apiListExportJobs.ForecastExportJobArn)

	var arn string
	if *apiListExportJobs.ForecastExportJobArn != "" {
		arn = string(*apiListExportJobs.ForecastExportJobArn)
	}

	var KmsKey string
	if *apiListExportJobs.Destination.S3Config.KMSKeyArn != "" {
		arn = string(*apiListExportJobs.Destination.S3Config.KMSKeyArn)
	}

	return &forecast.ListForecastExportJob{
		Metadata:             metadata,
		ForecastExportJobArn: types.String(arn, metadata),
		KMSKeyArn:            types.String(KmsKey, metadata),
	}, nil

}

func (a *adapter) adaptListDataset(apiListDatasets aatypes.DatasetSummary) (*forecast.ListDataset, error) {
	metadata := a.CreateMetadataFromARN(*apiListDatasets.DatasetArn)

	var arn string
	if *apiListDatasets.DatasetArn != "" {
		arn = string(*apiListDatasets.DatasetArn)
	}

	return &forecast.ListDataset{
		Metadata:   metadata,
		DatasetArn: types.String(arn, metadata),
	}, nil

}

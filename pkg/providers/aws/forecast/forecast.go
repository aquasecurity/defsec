package forecast

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Forecast struct {
	ListForecastExportJobs []ListForecastExportJob
	ListDatasets           []ListDataset
	DescribeDatasets       DescribeDataset
}

type ListForecastExportJob struct {
	Metadata             defsecTypes.Metadata
	ForecastExportJobArn defsecTypes.StringValue
	KMSKeyArn            defsecTypes.StringValue
}

type ListDataset struct {
	Metadata   defsecTypes.Metadata
	DatasetArn defsecTypes.StringValue
}

type DescribeDataset struct {
	Metadata  defsecTypes.Metadata
	KMSKeyArn defsecTypes.StringValue
}

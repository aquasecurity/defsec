package forecast

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/forecast"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) forecast.Forecast {
	return forecast.Forecast{
		ListForecastExportJobs: adaptForecastExportJobs(modules),
		DescribeDatasets:       adaptDescribeDatasets(modules),
		ListDatasets:           adaptListDatasets(modules),
	}
}

func adaptForecastExportJobs(modules terraform.Modules) []forecast.ListForecastExportJob {
	var ForecastJobsList []forecast.ListForecastExportJob
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("awscc_forecast_dataset") {
			ForecastJobsList = append(ForecastJobsList, adaptForecastExportJob(resource, module))
		}
	}
	return ForecastJobsList
}

func adaptForecastExportJob(resource *terraform.Block, module *terraform.Module) forecast.ListForecastExportJob {

	var Jobarn string

	TypeAttr := resource.GetAttribute("kms_key_arn")
	TypeVal := TypeAttr.AsStringValueOrDefault("", resource)

	return forecast.ListForecastExportJob{
		Metadata:             resource.GetMetadata(),
		KMSKeyArn:            TypeVal,
		ForecastExportJobArn: defsecTypes.String(Jobarn, defsecTypes.Metadata{}),
	}
}

func adaptListDatasets(modules terraform.Modules) []forecast.ListDataset {
	var ListDataset []forecast.ListDataset
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("awscc_forecast_dataset") {
			ListDataset = append(ListDataset, adaptListDataset(resource, module))
		}
	}
	return ListDataset
}

func adaptListDataset(resource *terraform.Block, module *terraform.Module) forecast.ListDataset {

	ArnAttr := resource.GetAttribute("arn")
	ArnVal := ArnAttr.AsStringValueOrDefault("", resource)

	return forecast.ListDataset{
		Metadata:   resource.GetMetadata(),
		DatasetArn: ArnVal,
	}
}

func adaptDescribeDatasets(modules terraform.Modules) forecast.DescribeDataset {
	var DescribeDataset forecast.DescribeDataset
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("awscc_forecast_dataset") {
			DescribeDataset = adaptDescribeDataset(resource, module)
		}
	}
	return DescribeDataset
}

func adaptDescribeDataset(resource *terraform.Block, module *terraform.Module) forecast.DescribeDataset {

	KmsAttr := resource.GetAttribute("kms_key_arn")
	KmsVal := KmsAttr.AsStringValueOrDefault("", resource)

	return forecast.DescribeDataset{
		Metadata:  resource.GetMetadata(),
		KMSKeyArn: KmsVal,
	}
}

package forecast

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/forecast"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListForecastDataset(ctx parser.FileContext) (forecastdatasetproperties []forecast.ListForecastExportJob) {

	forecastdataset := ctx.GetResourcesByType("AWS::Forecast::Dataset ")

	for _, r := range forecastdataset {

		fd := forecast.ListForecastExportJob{
			Metadata:             r.Metadata(),
			ForecastExportJobArn: r.GetStringProperty("Arn"),
			KMSKeyArn:            r.GetStringProperty("EncryptionConfig"),
		}
		forecastdatasetproperties = append(forecastdatasetproperties, fd)
	}

	return forecastdatasetproperties
}

package forecast

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/forecast"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) forecast.Forecast {
	return forecast.Forecast{
		ListDatasets: getListDatasets(cfFile),
		// DescribeDatasets: getDescribeDatasets(cFile),
		ListForecastExportJobs: getListForecastDataset(cfFile),
	}
}

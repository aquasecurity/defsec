package forecast

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/forecast"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getListDatasets(ctx parser.FileContext) (listdataset []forecast.ListDataset) {

	getListDataset := ctx.GetResourcesByType("AWS::Forecast::Dataset ")

	for _, r := range getListDataset {

		ld := forecast.ListDataset{
			Metadata:   r.Metadata(),
			DatasetArn: r.GetStringProperty("Arn"),
		}
		listdataset = append(listdataset, ld)
	}

	return listdataset
}

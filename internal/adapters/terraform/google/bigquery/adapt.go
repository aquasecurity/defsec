package bigquery

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/bigquery"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) bigquery.BigQuery {
	return bigquery.BigQuery{
		Datasets: adaptDatasets(modules),
		Tables:   adaptTables(modules),
	}
}

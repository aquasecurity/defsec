package google

import (
	"github.com/aquasecurity/defsec/provider/google/bigquery"
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/provider/google/dns"
	"github.com/aquasecurity/defsec/provider/google/gke"
	"github.com/aquasecurity/defsec/provider/google/kms"
	"github.com/aquasecurity/defsec/provider/google/platform"
	"github.com/aquasecurity/defsec/provider/google/sql"
	"github.com/aquasecurity/defsec/provider/google/storage"
	"github.com/aquasecurity/defsec/types"
)

type Google struct {
	types.Metadata
	BigQuery bigquery.BigQuery
	Compute  compute.Compute
	DNS      dns.DNS
	GKE      gke.GKE
	KMS      kms.KMS
	Platform platform.Platform
	SQL      sql.SQL
	Storage  storage.Storage
}

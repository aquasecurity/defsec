package documentdb

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableLogExport = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "enable-log-export",
		Summary:     "DocumentDB logs export should be enabled",
		Impact:      "Limited visibility of audit trail for changes to the DocumentDB",
		Resolution:  "Enable export logs",
		Explanation: `Document DB does not have auditing by default. To ensure that you are able to accurately audit the usage of your DocumentDB cluster you should enable export logs.`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			if cluster.EnabledLogExports.NotEqualTo(documentdb.LogExportAudit) && cluster.EnabledLogExports.NotEqualTo(documentdb.LogExportProfiler) {
				results.Add(
					"CloudWatch log exports are not enabled.",
					cluster.EnabledLogExports,
				)
			}
		}
		return
	},
)

package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnablePgTempFileLogging = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "enable-pg-temp-file-logging",
		Summary:     "Temporary file logging should be enabled for all temporary files.",
		Impact:      "Use of temporary files will not be logged",
		Resolution:  "Enable temporary file logging for all files",
		Explanation: `Temporary files are not logged by default. To log all temporary files, a value of ` + "`" + `0` + "`" + ` should set in the ` + "`" + `log_temp_files` + "`" + ` flag - as all files greater in size than the number of bytes set in this flag will be logged.`,
		Links: []string{ 
			"https://postgresqlco.nf/doc/en/param/log_temp_files/",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
					
				)
			}
		}
		return
	},
)

package rds

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEncryptClusterStorageData = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "rds",
		ShortCode:   "encrypt-cluster-storage-data",
		Summary:     "There is no encryption specified or encryption is disabled on the RDS Cluster.",
		Impact:      "Data can be read from the RDS cluster if it is compromised",
		Resolution:  "Enable encryption for RDS clusters",
		Explanation: `Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled.Metadata(),
					x.Encryption.Enabled.Value(),
				)
			}
		}
		return
	},
)

package emr

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-TODO-001",
		Provider:    providers.AWSProvider,
		Service:     "emr",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Enable at-rest encryption for EMR clusters.",
		Impact:      "At-rest data in the EMR cluster could be compromised if accessed.",
		Resolution:  "Enable at-rest encryption for EMR cluster",
		Explanation: `Data stored within an EMR cluster should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformEnableAtRestEncryptionBadExamples,
			Links:               terraformEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, emrSecurity := range s.AWS.EMR.SecurityConfiguration {
			// var foo = json.Unmarshal(emrSecurity.configuration, &foo)
			// fmt.Print(foo)
			if emrSecurity.EnableInTransitEncryption.IsFalse() && emrSecurity.EncryptionAtRestEnabled.IsFalse() {
				results.Add(
					"EMR cluster does not have at-rest encryption enabled.",
					emrSecurity.EncryptionAtRestEnabled,
				)
			} else {
				results.AddPassed(&emrSecurity)
			}
		}
		return
	},
)

// 	func(s *state.State) (results scan.Result) {
// 		for _, instance := range s.AWS.EMR.SecurityConfiguration {
// 			_foo = json.Unmarshal(instance.JSON, &_bar)
// 			if instance.EncryptionAtRestEnabled.IsFalse() {
// 				results.Add(
// 					"Security configuration does not have at-rest encryption enabled.",
// 					instance.AtRestEncryptionEnabled,
// 				)
// 			} else {
// 				results.AddPassed(&instance)
// 			}
// 			// if instance.EncryptionStatus == "UNENCRYPTED" {
// 			// 	results.Add(scan.Result{
// 			// 		Rule:     CheckEnableAtRestEncryption,
// 			// 		Severity: severity.High,
// 			// 		Message:  "Instance with unencrypted block device.",
// 			// 		Details:  "Instance with unencrypted block device.",
// 			// 	})
// 			// }
// 		}
// 		return
// 	},

// )

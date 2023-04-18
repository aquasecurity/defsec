package compute

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableShieldedVMSecureBoot = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0067",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-shielded-vm-sb",
		Summary:     "Instances should have Shielded VM secure boot enabled",
		Impact:      "Unable to verify digital signature of boot components, and unable to stop the boot process if verificaiton fails.",
		Resolution:  "Enable Shielded VM secure boot",
		Explanation: `Secure boot helps ensure that the system only runs authentic software.`,
		Links: []string{
			"https://cloud.google.com/security/shielded-cloud/shielded-vm#secure-boot",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableShieldedVmSbGoodExamples,
			BadExamples:         terraformEnableShieldedVmSbBadExamples,
			Links:               terraformEnableShieldedVmSbLinks,
			RemediationMarkdown: terraformEnableShieldedVmSbRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.ShieldedVM.SecureBootEnabled.IsFalse() {
				results.Add(
					"Instance does not have shielded VM secure boot enabled.",
					instance.ShieldedVM.SecureBootEnabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)

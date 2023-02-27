package emr

import (
	"encoding/json"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableLocalDiskEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0139",
		Provider:    providers.AWSProvider,
		Service:     "emr",
		ShortCode:   "enable-local-disk-encryption",
		Summary:     "Enable local-disk encryption for EMR clusters.",
		Impact:      "Local-disk data in the EMR cluster could be compromised if accessed.",
		Resolution:  "Enable local-disk encryption for EMR cluster",
		Explanation: `Data stored within an EMR instances should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableLocalDiskEncryptionGoodExamples,
			BadExamples:         terraformEnableLocalDiskEncryptionBadExamples,
			Links:               terraformEnableLocalDiskEncryptionLinks,
			RemediationMarkdown: terraformEnableLocalDiskEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, conf := range s.AWS.EMR.SecurityConfiguration {
			vars, err := readVarsFromConfigurationLocalDisk(conf.Configuration.Value())
			if err != nil {
				continue
			}

			if vars.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType == "" {
				results.Add(
					"EMR cluster does not have local-disk encryption enabled.",
					conf.Configuration,
				)
			} else {
				results.AddPassed(&conf)
			}

		}
		return
	},
)

func readVarsFromConfigurationLocalDisk(raw string) (*conf, error) {
	var testConf conf
	if err := json.Unmarshal([]byte(raw), &testConf); err != nil {
		return nil, err
	}

	return &testConf, nil
}

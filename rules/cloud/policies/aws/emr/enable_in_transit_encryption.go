package emr

import (
	"encoding/json"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0138",
		Provider:    providers.AWSProvider,
		Service:     "emr",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Enable in-transit encryption for EMR clusters.",
		Impact:      "In-transit data in the EMR cluster could be compromised if accessed.",
		Resolution:  "Enable in-transit encryption for EMR cluster",
		Explanation: `Data stored within an EMR cluster should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableInTransitEncryptionGoodExamples,
			BadExamples:         terraformEnableInTransitEncryptionBadExamples,
			Links:               terraformEnableInTransitEncryptionLinks,
			RemediationMarkdown: terraformEnableInTransitEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, conf := range s.AWS.EMR.SecurityConfiguration {
			vars, err := readVarsFromConfigurationInTransit(conf.Configuration.Value())
			if err != nil {
				continue
			}

			if !vars.EncryptionConfiguration.EnableInTransitEncryption {
				results.Add(
					"EMR cluster does not have in-transit encryption enabled.",
					conf.Configuration,
				)
			} else {
				results.AddPassed(&conf)
			}

		}
		return
	},
)

func readVarsFromConfigurationInTransit(raw string) (*conf, error) {
	var testConf conf
	if err := json.Unmarshal([]byte(raw), &testConf); err != nil {
		return nil, err
	}

	return &testConf, nil
}

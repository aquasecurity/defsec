package emr

import (
	"encoding/json"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0137",
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
		for _, conf := range s.AWS.EMR.SecurityConfiguration {
			vars, err := readVarsFromConfigurationAtRest(conf.Configuration.Value())
			if err != nil {
				continue
			}

			if !vars.EncryptionConfiguration.EnableAtRestEncryption {
				results.Add(
					"EMR cluster does not have at-rest encryption enabled.",
					conf.Configuration,
				)
			} else {
				results.AddPassed(&conf)
			}

		}
		return
	},
)

type conf struct {
	EncryptionConfiguration struct {
		AtRestEncryptionConfiguration struct {
			S3EncryptionConfiguration struct {
				EncryptionMode string `json:"EncryptionMode"`
			} `json:"S3EncryptionConfiguration"`
			LocalDiskEncryptionConfiguration struct {
				EncryptionKeyProviderType string `json:"EncryptionKeyProviderType"`
				AwsKmsKey                 string `json:"AwsKmsKey"`
			} `json:"LocalDiskEncryptionConfiguration"`
		} `json:"AtRestEncryptionConfiguration"`
		EnableInTransitEncryption bool `json:"EnableInTransitEncryption"`
		EnableAtRestEncryption    bool `json:"EnableAtRestEncryption"`
	} `json:"EncryptionConfiguration"`
}

func readVarsFromConfigurationAtRest(raw string) (*conf, error) {
	var testConf conf
	if err := json.Unmarshal([]byte(raw), &testConf); err != nil {
		return nil, err
	}

	return &testConf, nil
}

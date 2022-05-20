package emr

import (
	"encoding/json"
	"fmt"

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

		// scanner := squealer.NewStringScanner()

		for _, conf := range s.AWS.EMR.SecurityConfiguration {
			vars, err := readVarsFromConfiguration(conf.Configuration.Value())
			if err != nil {
				continue
			}
			// print vars
			fmt.Printf("Vars %s\n", vars)
			// fmt.Printf("Vars", vars)

			// fmt.Printf(vars)

			// for key, val := range vars {

			// if result := scanner.Scan(val); result.TransgressionFound || security.IsSensitiveAttribute(key) {
			// 	results.Add(
			// 		fmt.Sprintf("Container definition contains a potentially sensitive environment variable '%s': %s", key, result.Description),
			// 		conf.Configuration,
			// 	)
			// } else {
			// 	results.AddPassed(&conf)
			// }
			// }
		}
		return
	},
)

// resource "aws_emr_security_configuration" "foo" {
// 	name = "emrsc_other"

// 	configuration = <<EOF
//   {
// 	"EncryptionConfiguration": {
// 	  "AtRestEncryptionConfiguration": {
// 		"S3EncryptionConfiguration": {
// 		  "EncryptionMode": "SSE-S3"
// 		},
// 		"LocalDiskEncryptionConfiguration": {
// 		  "EncryptionKeyProviderType": "AwsKms",
// 		  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
// 		}
// 	  },
// 	  "EnableInTransitEncryption": false,
// 	  "EnableAtRestEncryption": true
// 	}
//   }
//   EOF
//   }

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

// func readEnvVarsFromContainerDefinitions(raw string) (map[string]string, error) {

// 	var definitions []definition
// 	if err := json.Unmarshal([]byte(raw), &definitions); err != nil {
// 		return nil, err
// 	}

// 	envVars := make(map[string]string)
// 	for _, definition := range definitions {
// 		for _, env := range definition.EnvVars {
// 			envVars[env.Name] = env.Value
// 		}
// 	}

// 	return envVars, nil
// }

func readVarsFromConfiguration(raw string) (map[string]string, error) {
	//map string to conf struct
	var confs []conf
	err := json.Unmarshal([]byte(raw), &confs)
	if err != nil {
		fmt.Printf("here")
		return nil, err
	}

	// //map string to string
	// vars := make(map[string]string)
	// for key, conf := range confs {
	// 	if conf.EncryptionConfiguration.EnableAtRestEncryption {
	// 		return

	// 	// if conf.EncryptionConfiguration.EnableAtRestEncryption {
	// 	// 	if conf.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode == "SSE-S3" {
	// 	// 		vars[key] = "SSE-S3"
	// 	// 	} else if conf.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType == "AwsKms" {
	// 	// 		vars[key] = conf.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.AwsKmsKey
	// 	// 	}
	// 	// }
	// }
	// return vars, nil
	// print confs
	// fmt.Printf(confs["EncryptionConfiguration"])
	// fmt.Printf("Confs %s\n", confs)
	return nil, nil
	// return confs, nil
}

// 	func(s *state.State) (results scan.Results) {
// 		for _, emrSecurity := range s.AWS.EMR.SecurityConfiguration {
// 			// var foo = json.Unmarshal(emrSecurity.configuration, &foo)
// 			// fmt.Print(foo)
// 			if emrSecurity.EnableInTransitEncryption.IsFalse() && emrSecurity.EncryptionAtRestEnabled.IsFalse() {
// 				results.Add(
// 					"EMR cluster does not have at-rest encryption enabled.",
// 					emrSecurity.EncryptionAtRestEnabled,
// 				)
// 			} else {
// 				results.AddPassed(&emrSecurity)
// 			}
// 		}
// 		return
// 	},
// )

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

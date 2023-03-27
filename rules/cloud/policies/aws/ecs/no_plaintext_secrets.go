package ecs

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"

	"github.com/owenrumney/squealer/pkg/squealer"
)

var CheckNoPlaintextSecrets = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0036",
		Provider:    providers.AWSProvider,
		Service:     "ecs",
		ShortCode:   "no-plaintext-secrets",
		Summary:     "Task definition defines sensitive environment variable(s).",
		Impact:      "Sensitive data could be exposed in the AWS Management Console",
		Resolution:  "Use secrets for the task definition",
		Explanation: `You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.`,
		Links: []string{
			"https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html",
			"https://www.vaultproject.io/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPlaintextSecretsGoodExamples,
			BadExamples:         terraformNoPlaintextSecretsBadExamples,
			Links:               terraformNoPlaintextSecretsLinks,
			RemediationMarkdown: terraformNoPlaintextSecretsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPlaintextSecretsGoodExamples,
			BadExamples:         cloudFormationNoPlaintextSecretsBadExamples,
			Links:               cloudFormationNoPlaintextSecretsLinks,
			RemediationMarkdown: cloudFormationNoPlaintextSecretsRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {

		scanner := squealer.NewStringScanner()

		for _, definition := range s.AWS.ECS.TaskDefinitions {
			for _, container := range definition.ContainerDefinitions {
				for _, env := range container.Environment {
					if result := scanner.Scan(env.Value); result.TransgressionFound || isSensitiveAttribute(env.Name) {
						results.Add(
							fmt.Sprintf("Container definition contains a potentially sensitive environment variable '%s': %s", env.Name, result.Description),
							container,
						)
					} else {
						results.AddPassed(&definition)
					}
				}
			}
		}
		return
	},
)

var sensitiveAttributeTokens = []string{
	"password",
	"secret",
	"private_key",
	"aws_access_key_id",
	"aws_secret_access_key",
	"token",
	"api_key",
}

var whitelistTokens = []string{
	"token_type",
	"version",
}

func isSensitiveAttribute(name string) bool {
	name = strings.ToLower(name)

	for _, criterionToken := range sensitiveAttributeTokens {
		if name == criterionToken {
			return true
		}
		if strings.Contains(name, criterionToken) {
			for _, exclusionToken := range whitelistTokens {
				if strings.HasSuffix(name, exclusionToken) {
					return false
				}
			}
			return true
		}
	}

	return false
}

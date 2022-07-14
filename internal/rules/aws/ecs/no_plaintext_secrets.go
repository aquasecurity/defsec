package ecs

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/internal/security"

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
					if result := scanner.Scan(env.Value); result.TransgressionFound || security.IsSensitiveAttribute(env.Name) {
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

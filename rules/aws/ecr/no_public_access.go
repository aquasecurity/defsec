package ecr

import (
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "ecr",
		ShortCode:   "no-public-access",
		Summary:     "ECR repository policy must block public access",
		Impact:      "Risk of potential data leakage of sensitive artifacts",
		Resolution:  "Do not allow public access in the policy",
		Explanation: `Allowing public access to the ECR repository risks leaking sensitive of abusable information`,
		Links:       []string{},
		Severity:    severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if !repo.IsManaged() {
				continue
			}
			for _, statement := range repo.Policy.Statements {
				var hasECRAction bool
				for _, action := range statement.Action {
					if strings.HasPrefix(action, "ecr:") {
						hasECRAction = true
						break
					}
				}
				if !hasECRAction {
					continue
				}
				for _, account := range statement.Principal.AWS {
					if account == "*" {
						results.Add(
							"Policy provides public access to the ECR repository.",
							repo.Policy.Metadata(),
						)
					}
					continue
				}
			}
		}
		return
	},
)

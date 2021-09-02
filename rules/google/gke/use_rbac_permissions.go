package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseRbacPermissions = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "use-rbac-permissions",
		Summary:     "Legacy ABAC permissions are enabled.",
		Impact:      "ABAC permissions are less secure than RBAC permissions",
		Resolution:  "Switch to using RBAC permissions",
		Explanation: `You should disable Attribute-Based Access Control (ABAC), and instead use Role-Based Access Control (RBAC) in GKE.

RBAC has significant security advantages and is now stable in Kubernetes, so it’s time to disable ABAC.`,
		Links: []string{ 
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110",
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

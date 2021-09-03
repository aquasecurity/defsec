package iam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoUserGrantedPermissions = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-user-granted-permissions",
		Summary:     "IAM granted directly to user.",
		Impact:      "Users shouldn't have permissions granted to them directly",
		Resolution:  "Roles should be granted permissions and assigned to users",
		Explanation: `Permissions should not be directly granted to users, you identify roles that contain the appropriate permissions, and then grant those roles to the user. 

Granting permissions to users quickly become unwieldy and complex to make large scale changes to remove access to a particular resource.

Permissions should be granted on roles, groups, services accounts instead.`,
		Links: []string{ 
			"https://cloud.google.com/iam/docs/overview#permissions",
			"https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy",
		},
		Severity: severity.Medium,
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

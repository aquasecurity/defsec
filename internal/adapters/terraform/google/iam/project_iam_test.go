package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_AdaptMember(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  iam.Member
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: iam.Member{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := AdaptMember(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_AdaptBinding(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.Binding
	}{
		{
			name: "defined",
			terraform: `
		resource "google_organization_iam_binding" "binding" {
			org_id = data.google_organization.org.id
			role    = "roles/browser"
			
			members = [
				"user:alice@gmail.com",
			]
		}`,
			expected: iam.Binding{
				Metadata: types2.NewTestMetadata(),
				Members: []types2.StringValue{
					types2.String("user:alice@gmail.com", types2.NewTestMetadata())},
				Role:                          types2.String("roles/browser", types2.NewTestMetadata()),
				IncludesDefaultServiceAccount: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
		resource "google_organization_iam_binding" "binding" {
		}`,
			expected: iam.Binding{
				Metadata:                      types2.NewTestMetadata(),
				Role:                          types2.String("", types2.NewTestMetadata()),
				IncludesDefaultServiceAccount: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := AdaptBinding(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

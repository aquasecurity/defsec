package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

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
				Metadata: types.NewTestMetadata(),
				Members: []types.StringValue{
					types.String("user:alice@gmail.com", types.NewTestMetadata())},
				Role:                          types.String("roles/browser", types.NewTestMetadata()),
				IncludesDefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
		resource "google_organization_iam_binding" "binding" {
		}`,
			expected: iam.Binding{
				Metadata:                      types.NewTestMetadata(),
				Role:                          types.String("", types.NewTestMetadata()),
				IncludesDefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
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

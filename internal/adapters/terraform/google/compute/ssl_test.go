package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptSSLPolicies(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.SSLPolicy
	}{
		{
			name: "defined",
			terraform: `
			resource "google_compute_ssl_policy" "example" {
				name    = "production-ssl-policy"
				profile = "MODERN"
				min_tls_version = "TLS_1_2"
			  }
`,
			expected: []compute.SSLPolicy{
				{
					Metadata:          types.NewTestMetadata(),
					Name:              types.String("production-ssl-policy", types.NewTestMetadata()),
					Profile:           types.String("MODERN", types.NewTestMetadata()),
					MinimumTLSVersion: types.String("TLS_1_2", types.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_ssl_policy" "example" {
			  }
`,
			expected: []compute.SSLPolicy{
				{
					Metadata:          types.NewTestMetadata(),
					Name:              types.String("", types.NewTestMetadata()),
					Profile:           types.String("", types.NewTestMetadata()),
					MinimumTLSVersion: types.String("TLS_1_0", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSSLPolicies(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

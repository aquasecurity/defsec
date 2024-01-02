package vpn

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/vpn"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptVpnEndpoint(t *testing.T) {
	tests := []struct {
		name	string
		terraform string
		expected vpn.VpnEndpoint
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_ec2_client_vpn_endpoint" "example" {
				client_login_banner_options		= "test-configuration"
			}
`,
			expected: vpn.VpnEndpoint{
				Metadata: defsecTypes.NewTestMetadata(),
				BannerOptions: defsecTypes.String("test-configuration", defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ec2_client_vpn_endpoint" "example" {
			}
`,
			expected: vpn.VpnEndpoint{
				Metadata: defsecTypes.NewTestMetadata(),
				BannerOptions: defsecTypes.String("", defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptVpn(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_ec2_client_vpn_endpoint" "example" {
		client_login_banner_options		= "test-configuration"
	}`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Vpns, 1)
	vpn := adapted.Vpns[0]
	
	assert.Equal(t, 2, vpn.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, vpn.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, vpn.BannerOptions.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, vpn.BannerOptions.GetMetadata().Range().GetEndLine())
}

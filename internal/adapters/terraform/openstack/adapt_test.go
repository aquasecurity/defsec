package openstack

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/openstack"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFields(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  openstack.OpenStack
	}{
		{
			name: "Plaintext password",
			terraform: `
			resource "openstack_compute_instance_v2" "my-instance" {
			  admin_pass      = "N0tSoS3cretP4ssw0rd"

			}`,
			expected: openstack.OpenStack{
				Compute: openstack.Compute{
					Instances: []openstack.Instance{
						{
							Metadata:      types2.NewTestMetadata(),
							AdminPassword: types2.String("N0tSoS3cretP4ssw0rd", types2.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "No plaintext password",
			terraform: `
			resource "openstack_compute_instance_v2" "my-instance" {
			}`,
			expected: openstack.OpenStack{
				Compute: openstack.Compute{
					Instances: []openstack.Instance{
						{
							Metadata:      types2.NewTestMetadata(),
							AdminPassword: types2.String("", types2.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "Firewall rule",
			terraform: `
			resource "openstack_fw_rule_v1" "rule_1" {
				action                 = "allow"
				protocol               = "tcp"
				destination_port       = "22"
				destination_ip_address = "10.10.10.1"
				source_ip_address      = "10.10.10.2"
				enabled                = "true"
			}`,
			expected: openstack.OpenStack{
				Compute: openstack.Compute{
					Firewall: openstack.Firewall{
						AllowRules: []openstack.FirewallRule{
							{
								Metadata:        types2.NewTestMetadata(),
								Enabled:         types2.Bool(true, types2.NewTestMetadata()),
								Destination:     types2.String("10.10.10.1", types2.NewTestMetadata()),
								Source:          types2.String("10.10.10.2", types2.NewTestMetadata()),
								DestinationPort: types2.String("22", types2.NewTestMetadata()),
								SourcePort:      types2.String("", types2.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "openstack_compute_instance_v2" "my-instance" {
		admin_pass      = "N0tSoS3cretP4ssw0rd"
	}

	resource "openstack_fw_rule_v1" "rule_1" {
		action                 = "allow"
		protocol               = "tcp"
		destination_port       = "22"
		destination_ip_address = "10.10.10.1"
		source_ip_address      = "10.10.10.2"
		enabled                = "true"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Compute.Instances, 1)
	instance := adapted.Compute.Instances[0]

	require.Len(t, adapted.Compute.Firewall.AllowRules, 1)
	rule := adapted.Compute.Firewall.AllowRules[0]

	assert.Equal(t, 3, instance.AdminPassword.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, instance.AdminPassword.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, rule.DestinationPort.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, rule.DestinationPort.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, rule.Destination.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, rule.Destination.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, rule.Source.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, rule.Source.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, rule.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, rule.Enabled.GetMetadata().Range().GetEndLine())
}

package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Instance
	}{
		{
			name: "defined",
			terraform: `
			resource "google_service_account" "default" {
			  }
		  
			resource "google_compute_instance" "example" {
				name         = "test"
		
				boot_disk {
					device_name = "boot-disk"
					kms_key_self_link = "something"
				  }
			  
				shielded_instance_config {
				  enable_integrity_monitoring = true
				  enable_vtpm = true
				  enable_secure_boot = true
				}

				network_interface {
					network = "default"
				
					access_config {
					}
				  }

				  service_account {
					email  = google_service_account.default.email
					scopes = ["cloud-platform"]
				  }
				  can_ip_forward = true

				  metadata = {
					enable-oslogin = false
					block-project-ssh-keys = true
					serial-port-enable = true
				  }
			  }
`,
			expected: []compute.Instance{
				{
					Metadata: types.NewTestMetadata(),
					Name:     types.String("test", types.NewTestMetadata()),
					NetworkInterfaces: []compute.NetworkInterface{
						{
							Metadata:    types.NewTestMetadata(),
							HasPublicIP: types.Bool(true, types.NewTestMetadata()),
							NATIP:       types.String("", types.NewTestMetadata()),
						},
					},
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   types.NewTestMetadata(),
						SecureBootEnabled:          types.Bool(true, types.NewTestMetadata()),
						IntegrityMonitoringEnabled: types.Bool(true, types.NewTestMetadata()),
						VTPMEnabled:                types.Bool(true, types.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata: types.NewTestMetadata(),
						Email:    types.String("google_service_account.default", types.NewTestMetadata()),
						Scopes: []types.StringValue{
							types.String("cloud-platform", types.NewTestMetadata()),
						},
					},
					CanIPForward:                types.Bool(true, types.NewTestMetadata()),
					OSLoginEnabled:              types.Bool(false, types.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: types.Bool(true, types.NewTestMetadata()),
					EnableSerialPort:            types.Bool(true, types.NewTestMetadata()),

					BootDisks: []compute.Disk{
						{
							Metadata: types.NewTestMetadata(),
							Name:     types.String("boot-disk", types.NewTestMetadata()),
							Encryption: compute.DiskEncryption{
								Metadata:   types.NewTestMetadata(),
								KMSKeyLink: types.String("something", types.NewTestMetadata()),
								RawKey:     nil,
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_instance" "example" {
			  }
`,
			expected: []compute.Instance{
				{
					Metadata: types.NewTestMetadata(),
					Name:     types.String("", types.NewTestMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   types.NewTestMetadata(),
						SecureBootEnabled:          types.Bool(false, types.NewTestMetadata()),
						IntegrityMonitoringEnabled: types.Bool(false, types.NewTestMetadata()),
						VTPMEnabled:                types.Bool(false, types.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata: types.NewTestMetadata(),
						Email:    types.String("", types.NewTestMetadata()),
					},
					CanIPForward:                types.Bool(false, types.NewTestMetadata()),
					OSLoginEnabled:              types.Bool(true, types.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: types.Bool(false, types.NewTestMetadata()),
					EnableSerialPort:            types.Bool(false, types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

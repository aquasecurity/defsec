package compute

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
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
					Metadata: types2.NewTestMetadata(),
					Name:     types2.String("test", types2.NewTestMetadata()),
					NetworkInterfaces: []compute.NetworkInterface{
						{
							Metadata:    types2.NewTestMetadata(),
							HasPublicIP: types2.Bool(true, types2.NewTestMetadata()),
							NATIP:       types2.String("", types2.NewTestMetadata()),
						},
					},
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   types2.NewTestMetadata(),
						SecureBootEnabled:          types2.Bool(true, types2.NewTestMetadata()),
						IntegrityMonitoringEnabled: types2.Bool(true, types2.NewTestMetadata()),
						VTPMEnabled:                types2.Bool(true, types2.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata: types2.NewTestMetadata(),
						Email:    types2.String("google_service_account.default", types2.NewTestMetadata()),
						Scopes: []types2.StringValue{
							types2.String("cloud-platform", types2.NewTestMetadata()),
						},
					},
					CanIPForward:                types2.Bool(true, types2.NewTestMetadata()),
					OSLoginEnabled:              types2.Bool(false, types2.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: types2.Bool(true, types2.NewTestMetadata()),
					EnableSerialPort:            types2.Bool(true, types2.NewTestMetadata()),

					BootDisks: []compute.Disk{
						{
							Metadata: types2.NewTestMetadata(),
							Name:     types2.String("boot-disk", types2.NewTestMetadata()),
							Encryption: compute.DiskEncryption{
								Metadata:   types2.NewTestMetadata(),
								KMSKeyLink: types2.String("something", types2.NewTestMetadata()),
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
					Metadata: types2.NewTestMetadata(),
					Name:     types2.String("", types2.NewTestMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   types2.NewTestMetadata(),
						SecureBootEnabled:          types2.Bool(false, types2.NewTestMetadata()),
						IntegrityMonitoringEnabled: types2.Bool(false, types2.NewTestMetadata()),
						VTPMEnabled:                types2.Bool(false, types2.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata: types2.NewTestMetadata(),
						Email:    types2.String("", types2.NewTestMetadata()),
					},
					CanIPForward:                types2.Bool(false, types2.NewTestMetadata()),
					OSLoginEnabled:              types2.Bool(true, types2.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: types2.Bool(false, types2.NewTestMetadata()),
					EnableSerialPort:            types2.Bool(false, types2.NewTestMetadata()),
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

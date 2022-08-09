package compute

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptDisks(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Disk
	}{
		{
			name: "key as string link or raw bytes",
			terraform: `
			resource "google_compute_disk" "example-one" {
				name  = "disk #1"
			
				disk_encryption_key {
				  kms_key_self_link = "something"
				}
			  }

			  resource "google_compute_disk" "example-two" {
				name  = "disk #2"
			
				disk_encryption_key {
				  raw_key="b2ggbm8gdGhpcyBpcyBiYWQ"
				}
			  }
`,
			expected: []compute.Disk{
				{
					Metadata: types2.NewTestMetadata(),
					Name:     types2.String("disk #1", types2.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   types2.NewTestMetadata(),
						KMSKeyLink: types2.String("something", types2.NewTestMetadata()),
						RawKey:     nil,
					},
				},
				{
					Metadata: types2.NewTestMetadata(),
					Name:     types2.String("disk #2", types2.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   types2.NewTestMetadata(),
						KMSKeyLink: types2.String("", types2.NewTestMetadata()),
						RawKey:     types2.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), types2.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "key link as reference",
			terraform: `
			resource "google_kms_crypto_key" "my_crypto_key" {
				name            = "crypto-key-example"
			  }

			resource "google_compute_disk" "example-three" {
				name  = "disk #3"
			
				disk_encryption_key {
					kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
				}
			  }`,
			expected: []compute.Disk{
				{
					Metadata: types2.NewTestMetadata(),
					Name:     types2.String("disk #3", types2.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   types2.NewTestMetadata(),
						KMSKeyLink: types2.String("google_kms_crypto_key.my_crypto_key", types2.NewTestMetadata()),
						RawKey:     nil,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDisks(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

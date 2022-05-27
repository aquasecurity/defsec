package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

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
					Metadata: types.NewTestMetadata(),
					Name:     types.String("disk #1", types.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   types.NewTestMetadata(),
						KMSKeyLink: types.String("something", types.NewTestMetadata()),
						RawKey:     nil,
					},
				},
				{
					Metadata: types.NewTestMetadata(),
					Name:     types.String("disk #2", types.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   types.NewTestMetadata(),
						KMSKeyLink: types.String("", types.NewTestMetadata()),
						RawKey:     types.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), types.NewTestMetadata()),
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
					Metadata: types.NewTestMetadata(),
					Name:     types.String("disk #3", types.NewTestMetadata()),
					Encryption: compute.DiskEncryption{
						Metadata:   types.NewTestMetadata(),
						KMSKeyLink: types.String("google_kms_crypto_key.my_crypto_key", types.NewTestMetadata()),
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

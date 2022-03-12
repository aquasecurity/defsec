package kms

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/google/kms"
)

func Test_adaptKeyRings(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []kms.KeyRing
	}{
		{
			name: "configured",
			terraform: `
			resource "google_kms_key_ring" "keyring" {
				name     = "keyring-example"
			  }
			  
			  resource "google_kms_crypto_key" "example-key" {
				name            = "crypto-key-example"
				key_ring        = google_kms_key_ring.keyring.id
				rotation_period = "7776000s"
			  }
`,
			expected: []kms.KeyRing{
				{
					Metadata: types.NewTestMetadata(),
					Keys: []kms.Key{
						{
							Metadata:              types.NewTestMetadata(),
							RotationPeriodSeconds: types.Int(7776000, types.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "no keys",
			terraform: `
			resource "google_kms_key_ring" "keyring" {
				name     = "keyring-example"
			  }

`,
			expected: []kms.KeyRing{
				{
					Metadata: types.NewTestMetadata(),
				},
			},
		},
		{
			name: "default rotation period",
			terraform: `
			resource "google_kms_key_ring" "keyring" {
				name     = "keyring-example"
			  }
			  
			  resource "google_kms_crypto_key" "example-key" {
				name            = "crypto-key-example"
				key_ring        = google_kms_key_ring.keyring.id
			  }
`,
			expected: []kms.KeyRing{
				{
					Metadata: types.NewTestMetadata(),
					Keys: []kms.Key{
						{
							Metadata:              types.NewTestMetadata(),
							RotationPeriodSeconds: types.Int(-1, types.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptKeyRings(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "google_kms_key_ring" "keyring" {
		name     = "keyring-example"
	  }
	  
	  resource "google_kms_crypto_key" "example-key" {
		name            = "crypto-key-example"
		key_ring        = google_kms_key_ring.keyring.id
		rotation_period = "7776000s"
	  }`

	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	adapted := Adapt(modules)

	require.Len(t, adapted.KeyRings, 1)
	require.Len(t, adapted.KeyRings[0].Keys, 1)

	key := adapted.KeyRings[0].Keys[0]

	assert.Equal(t, 2, adapted.KeyRings[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, adapted.KeyRings[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, key.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, key.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, key.RotationPeriodSeconds.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, key.RotationPeriodSeconds.GetMetadata().Range().GetEndLine())

}

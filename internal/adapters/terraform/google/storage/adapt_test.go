package storage

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/providers/google/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  storage.Storage
	}{
		{
			name: "defined",
			terraform: `
			resource "google_storage_bucket" "static-site" {
				name          = "image-store.com"
				location      = "EU"				
				uniform_bucket_level_access = true
			}

			resource "google_storage_bucket_iam_binding" "binding" {
				bucket = google_storage_bucket.static-site.name
				role = "roles/storage.admin #1"
				members = [
					"group:test@example.com",
				]
			}

			resource "google_storage_bucket_iam_member" "example" {
				member = "serviceAccount:test@example.com"
				bucket = google_storage_bucket.static-site.name
				role = "roles/storage.admin #2"
			}`,
			expected: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       types.NewTestMetadata(),
						Name:                           types.String("image-store.com", types.NewTestMetadata()),
						Location:                       types.String("EU", types.NewTestMetadata()),
						EnableUniformBucketLevelAccess: types.Bool(true, types.NewTestMetadata()),
						Bindings: []iam.Binding{
							{
								Metadata: types.NewTestMetadata(),
								Members: []types.StringValue{
									types.String("group:test@example.com", types.NewTestMetadata()),
								},
								Role:                          types.String("roles/storage.admin #1", types.NewTestMetadata()),
								IncludesDefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
							},
						},
						Members: []iam.Member{
							{
								Metadata:              types.NewTestMetadata(),
								Member:                types.String("serviceAccount:test@example.com", types.NewTestMetadata()),
								Role:                  types.String("roles/storage.admin #2", types.NewTestMetadata()),
								DefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_storage_bucket" "static-site" {	
			}

			resource "google_storage_bucket_iam_binding" "binding" {
				bucket = google_storage_bucket.static-site.name
			}

			resource "google_storage_bucket_iam_member" "example" {
				bucket = google_storage_bucket.static-site.name
			}

`,
			expected: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       types.NewTestMetadata(),
						Name:                           types.String("", types.NewTestMetadata()),
						Location:                       types.String("", types.NewTestMetadata()),
						EnableUniformBucketLevelAccess: types.Bool(false, types.NewTestMetadata()),
						Bindings: []iam.Binding{
							{
								Metadata:                      types.NewTestMetadata(),
								Role:                          types.String("", types.NewTestMetadata()),
								IncludesDefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
							},
						},
						Members: []iam.Member{
							{
								Metadata:              types.NewTestMetadata(),
								Member:                types.String("", types.NewTestMetadata()),
								Role:                  types.String("", types.NewTestMetadata()),
								DefaultServiceAccount: types.Bool(false, types.NewTestMetadata()),
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
	resource "google_storage_bucket" "static-site" {
		name          = "image-store.com"
		location      = "EU"				
		uniform_bucket_level_access = true
	}

	resource "google_storage_bucket_iam_binding" "binding" {
		bucket = google_storage_bucket.static-site.name
		role = "roles/storage.admin #1"
		members = [
			"group:test@example.com",
		]
	}

	resource "google_storage_bucket_iam_member" "example" {
		member = "serviceAccount:test@example.com"
		bucket = google_storage_bucket.static-site.name
		role = "roles/storage.admin #2"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Buckets, 1)
	require.Len(t, adapted.Buckets[0].Bindings, 1)
	require.Len(t, adapted.Buckets[0].Members, 1)

	bucket := adapted.Buckets[0]
	binding := adapted.Buckets[0].Bindings[0]
	member := adapted.Buckets[0].Members[0]

	assert.Equal(t, 2, bucket.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, bucket.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, bucket.Location.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, bucket.Location.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, bucket.EnableUniformBucketLevelAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, bucket.EnableUniformBucketLevelAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, binding.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, binding.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, binding.Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, binding.Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, binding.Members[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, binding.Members[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, member.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, member.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, member.Member.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, member.Member.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, member.Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, member.Role.GetMetadata().Range().GetEndLine())
}

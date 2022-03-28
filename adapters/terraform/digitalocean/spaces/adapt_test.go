package spaces

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/digitalocean/spaces"
)

func Test_adaptBuckets(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []spaces.Bucket
	}{
		{
			name: "basic",
			terraform: `
			resource "digitalocean_spaces_bucket" "example" {
				name   = "public_space"
				region = "nyc3"
				acl    = "private"

				force_destroy = true

				versioning {
					enabled = true
				  }
			  }
			  
			  resource "digitalocean_spaces_bucket_object" "index" {
				bucket       = digitalocean_spaces_bucket.example.name
				acl          = "private"
			  }
`,
			expected: []spaces.Bucket{
				{
					Metadata: types.NewTestMetadata(),
					Name:     types.String("public_space", types.NewTestMetadata()),
					Objects: []spaces.Object{
						{
							Metadata: types.NewTestMetadata(),
							ACL:      types.String("private", types.NewTestMetadata()),
						},
					},
					ACL:          types.String("private", types.NewTestMetadata()),
					ForceDestroy: types.Bool(true, types.NewTestMetadata()),
					Versioning: spaces.Versioning{
						Metadata: types.NewTestMetadata(),
						Enabled:  types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "digitalocean_spaces_bucket" "example" {
			  }
			
`,
			expected: []spaces.Bucket{
				{
					Metadata:     types.NewTestMetadata(),
					Name:         types.String("", types.NewTestMetadata()),
					Objects:      nil,
					ACL:          types.String("public-read", types.NewTestMetadata()),
					ForceDestroy: types.Bool(false, types.NewTestMetadata()),
					Versioning: spaces.Versioning{
						Metadata: types.NewTestMetadata(),
						Enabled:  types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptBuckets(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "digitalocean_spaces_bucket" "example" {
		name   = "public_space"
		region = "nyc3"
		acl    = "private"

		force_destroy = true

		versioning {
			enabled = true
		  }
	  }
	  
	  resource "digitalocean_spaces_bucket_object" "index" {
		bucket       = digitalocean_spaces_bucket.example.name
		acl          = "public-read"
	  }
	`

	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	adapted := Adapt(modules)

	require.Len(t, adapted.Buckets, 1)
	bucket := adapted.Buckets[0]

	assert.Equal(t, 2, bucket.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, bucket.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, bucket.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, bucket.ACL.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, bucket.ACL.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, bucket.ForceDestroy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, bucket.ForceDestroy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, bucket.Versioning.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, bucket.Versioning.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, bucket.Versioning.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, bucket.Versioning.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, bucket.Objects[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, bucket.Objects[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, bucket.Objects[0].ACL.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, bucket.Objects[0].ACL.GetMetadata().Range().GetEndLine())

}

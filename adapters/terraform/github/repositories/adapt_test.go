package repositories

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
)

func Test_AdaptDefaults(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	
}
`
	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.True(t, repo.Public.IsTrue())
}

func Test_Adapt_Private(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	private = true
}
`
	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.False(t, repo.Public.IsTrue())
	assert.Equal(t, 3, repo.Public.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, repo.Public.GetMetadata().Range().GetEndLine())
}

func Test_Adapt_Public(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	private = false
}
`
	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.True(t, repo.Public.IsTrue())
	assert.Equal(t, 3, repo.Public.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, repo.Public.GetMetadata().Range().GetEndLine())
}

func Test_Adapt_VisibilityOverride(t *testing.T) {

	src := `
resource "github_repository" "my-repo" {
	private = true
	visibility = "public"
}
`
	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	repositories := Adapt(modules)
	require.Len(t, repositories, 1)
	repo := repositories[0]

	assert.True(t, repo.Public.IsTrue())
	assert.Equal(t, 4, repo.Public.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, repo.Public.GetMetadata().Range().GetEndLine())
}

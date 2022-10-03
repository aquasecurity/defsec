package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.IAM
	}{
		{
			name: "basic",
			terraform: `
			data "google_organization" "org" {
				domain = "example.com"
			  }
				  
			  resource "google_project" "my_project" {
				name       = "My Project"
				project_id = "your-project-id"
				org_id = data.google_organization.org.id
				auto_create_network = true
			  }

			  resource "google_folder" "department1" {
				display_name = "Department 1"
				parent       = data.google_organization.org.id
			  }

			  resource "google_folder_iam_member" "admin" {
				folder = google_folder.department1.name
				role   = "roles/editor"
				member = "user:alice@gmail.com"
			  }

			resource "google_folder_iam_binding" "folder-123" {
				folder = google_folder.department1.name
				role    = "roles/nothing"
				members = [
					"user:not-alice@gmail.com",
				  ]
		 	  }

			resource "google_organization_iam_member" "org-123" {
					org_id = data.google_organization.org.id
					role    = "roles/whatever"
					member = "user:member@gmail.com"
		 	 }

			resource "google_organization_iam_binding" "binding" {
				org_id = data.google_organization.org.id
				role    = "roles/browser"
				
				members = [
					"user:member_2@gmail.com",
				]
			  }
`,
			expected: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: defsecTypes.NewTestMetadata(),

						Projects: []iam.Project{
							{
								Metadata:          defsecTypes.NewTestMetadata(),
								AutoCreateNetwork: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							},
						},

						Folders: []iam.Folder{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              defsecTypes.NewTestMetadata(),
										Member:                defsecTypes.String("user:alice@gmail.com", defsecTypes.NewTestMetadata()),
										Role:                  defsecTypes.String("roles/editor", defsecTypes.NewTestMetadata()),
										DefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Members: []defsecTypes.StringValue{
											defsecTypes.String("user:not-alice@gmail.com", defsecTypes.NewTestMetadata()),
										},
										Role:                          defsecTypes.String("roles/nothing", defsecTypes.NewTestMetadata()),
										IncludesDefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
									},
								},
							},
						},
						Members: []iam.Member{
							{
								Metadata:              defsecTypes.NewTestMetadata(),
								Member:                defsecTypes.String("user:member@gmail.com", defsecTypes.NewTestMetadata()),
								Role:                  defsecTypes.String("roles/whatever", defsecTypes.NewTestMetadata()),
								DefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Members: []defsecTypes.StringValue{
									defsecTypes.String("user:member_2@gmail.com", defsecTypes.NewTestMetadata())},
								Role:                          defsecTypes.String("roles/browser", defsecTypes.NewTestMetadata()),
								IncludesDefaultServiceAccount: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
		data "google_organization" "org" {
			domain = "example.com"
		}
			
		resource "google_project" "my_project" {
			name       = "My Project"
			project_id = "your-project-id"
			org_id = data.google_organization.org.id
			auto_create_network = true
		}

		resource "google_folder" "department1" {
			display_name = "Department 1"
			parent       = data.google_organization.org.id
		}

		resource "google_folder_iam_binding" "folder-123" {
			folder = google_folder.department1.name
			role    = "roles/nothing"
			members = [
				"user:not-alice@gmail.com",
			]
		}

		resource "google_folder_iam_member" "admin" {
			folder = google_folder.department1.name
			role   = "roles/editor"
			member = "user:alice@gmail.com"
		}

		resource "google_organization_iam_member" "org-123" {
				org_id = data.google_organization.org.id
				role    = "roles/whatever"
				member = "user:member@gmail.com"
		}

		resource "google_organization_iam_binding" "binding" {
			org_id = data.google_organization.org.id
			role    = "roles/browser"
			
			members = [
				"user:member_2@gmail.com",
			]
		}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Organizations, 1)
	require.Len(t, adapted.Organizations[0].Projects, 1)
	require.Len(t, adapted.Organizations[0].Folders, 1)
	require.Len(t, adapted.Organizations[0].Bindings, 1)
	require.Len(t, adapted.Organizations[0].Members, 1)

	project := adapted.Organizations[0].Projects[0]
	folder := adapted.Organizations[0].Folders[0]
	binding := adapted.Organizations[0].Bindings[0]
	member := adapted.Organizations[0].Members[0]

	assert.Equal(t, 6, project.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, project.Metadata.Range().GetEndLine())

	assert.Equal(t, 10, project.AutoCreateNetwork.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, project.AutoCreateNetwork.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, folder.Metadata.Range().GetStartLine())
	assert.Equal(t, 16, folder.Metadata.Range().GetEndLine())

	assert.Equal(t, 18, folder.Bindings[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 24, folder.Bindings[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 20, folder.Bindings[0].Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, folder.Bindings[0].Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, folder.Bindings[0].Members[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, folder.Bindings[0].Members[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, folder.Members[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 30, folder.Members[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 29, folder.Members[0].Member.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 29, folder.Members[0].Member.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 28, folder.Members[0].Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, folder.Members[0].Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 32, member.Metadata.Range().GetStartLine())
	assert.Equal(t, 36, member.Metadata.Range().GetEndLine())

	assert.Equal(t, 34, member.Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, member.Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 35, member.Member.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 35, member.Member.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, binding.Metadata.Range().GetStartLine())
	assert.Equal(t, 45, binding.Metadata.Range().GetEndLine())

	assert.Equal(t, 40, binding.Role.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 40, binding.Role.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 42, binding.Members[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 44, binding.Members[0].GetMetadata().Range().GetEndLine())
}

package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/google/uuid"
)

func Adapt(modules terraform.Modules) iam.IAM {
	return (&adapter{
		orgs:    make(map[string]iam.Organization),
		modules: modules,
	}).Adapt()
}

type adapter struct {
	modules  terraform.Modules
	orgs     map[string]iam.Organization
	folders  []parentedFolder
	projects []parentedProject
}

func (a *adapter) Adapt() iam.IAM {
	a.adaptOrganizationIAM()
	a.adaptFolders()
	a.adaptFolderIAM()
	a.adaptProjects()
	a.adaptProjectIAM()
	return a.merge()
}

func (a *adapter) addOrg(blockID string) {
	if _, ok := a.orgs[blockID]; !ok {
		a.orgs[blockID] = iam.Organization{
			Metadata: types.NewUnmanagedMetadata(),
		}
	}
}

func (a *adapter) merge() iam.IAM {

	// add projects to folders, orgs
PROJECT:
	for _, project := range a.projects {
		for i, folder := range a.folders {
			if project.folderBlockID != "" && project.folderBlockID == folder.blockID {
				folder.folder.Projects = append(folder.folder.Projects, project.project)
				a.folders[i] = folder
				continue PROJECT
			}
		}
		if project.orgBlockID != "" {
			if org, ok := a.orgs[project.orgBlockID]; ok {
				org.Projects = append(org.Projects, project.project)
				a.orgs[project.orgBlockID] = org
				continue PROJECT
			}
		}

		org := iam.Organization{
			Metadata: types.NewUnmanagedMetadata(),
			Projects: []iam.Project{project.project},
		}
		a.orgs[uuid.NewString()] = org
	}

	// add folders to folders, orgs
FOLDER_NESTED:
	for _, folder := range a.folders {
		for i, existing := range a.folders {
			if folder.parentBlockID != "" && folder.parentBlockID == existing.blockID {
				existing.folder.Folders = append(existing.folder.Folders, folder.folder)
				a.folders[i] = existing
				continue FOLDER_NESTED
			}

		}
	}
FOLDER_ORG:
	for _, folder := range a.folders {
		if folder.parentBlockID != "" {
			if org, ok := a.orgs[folder.parentBlockID]; ok {
				org.Folders = append(org.Folders, folder.folder)
				a.orgs[folder.parentBlockID] = org
				continue FOLDER_ORG
			}
		} else {
			// add to placeholder?
			org := iam.Organization{
				Metadata: types.NewUnmanagedMetadata(),
				Folders:  []iam.Folder{folder.folder},
			}
			a.orgs[uuid.NewString()] = org
		}
	}

	output := iam.IAM{
		Organizations: nil,
	}
	for _, org := range a.orgs {
		output.Organizations = append(output.Organizations, org)
	}
	return output
}

package iam

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type IAM struct {
	Organizations []Organization
}

type Organization struct {
	defsecTypes.Metadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	defsecTypes.Metadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Project struct {
	defsecTypes.Metadata
	AutoCreateNetwork defsecTypes.BoolValue
	Members           []Member
	Bindings          []Binding
}

type Binding struct {
	defsecTypes.Metadata
	Members                       []defsecTypes.StringValue
	Role                          defsecTypes.StringValue
	IncludesDefaultServiceAccount defsecTypes.BoolValue
}

type Member struct {
	defsecTypes.Metadata
	Member                defsecTypes.StringValue
	Role                  defsecTypes.StringValue
	DefaultServiceAccount defsecTypes.BoolValue
}

func (p *IAM) AllProjects() []Project {
	var projects []Project
	for _, org := range p.Organizations {
		projects = append(projects, org.Projects...)
		for _, folder := range org.Folders {
			projects = append(projects, folder.Projects...)
			for _, desc := range folder.AllFolders() {
				projects = append(projects, desc.Projects...)
			}
		}
	}
	return projects
}

func (p *IAM) AllFolders() []Folder {
	var folders []Folder
	for _, org := range p.Organizations {
		folders = append(folders, org.Folders...)
		for _, folder := range org.Folders {
			folders = append(folders, folder.AllFolders()...)
		}
	}
	return folders
}

func (f *Folder) AllFolders() []Folder {
	var folders []Folder
	for _, folder := range f.Folders {
		folders = append(folders, folder)
		folders = append(folders, folder.AllFolders()...)
	}
	return folders
}

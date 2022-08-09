package iam

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type IAM struct {
	Organizations []Organization
}

type Organization struct {
	types2.Metadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	types2.Metadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Project struct {
	types2.Metadata
	AutoCreateNetwork types2.BoolValue
	Members           []Member
	Bindings          []Binding
}

type Binding struct {
	types2.Metadata
	Members                       []types2.StringValue
	Role                          types2.StringValue
	IncludesDefaultServiceAccount types2.BoolValue
}

type Member struct {
	types2.Metadata
	Member                types2.StringValue
	Role                  types2.StringValue
	DefaultServiceAccount types2.BoolValue
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

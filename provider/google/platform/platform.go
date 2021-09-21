package platform

import "github.com/aquasecurity/defsec/types"

type Platform struct {
	Organizations []Organization
}

func (p *Platform) AllProjects() []Project {
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

func (p *Platform) AllFolders() []Folder {
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

type Organization struct {
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Member struct {
	Member types.StringValue
	Role   types.StringValue
}

type Binding struct {
	Members []types.StringValue
	Role    types.StringValue
}

type Project struct {
	AutoCreateNetwork types.BoolValue
	Members           []Member
	Bindings          []Binding
}

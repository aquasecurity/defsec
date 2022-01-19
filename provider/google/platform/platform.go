package platform

import (
	"github.com/aquasecurity/defsec/provider/google/iam"
	"github.com/aquasecurity/defsec/types"
)

type Platform struct {
	types.Metadata
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
	types.Metadata
	Folders  []Folder
	Projects []Project
	Members  []iam.Member
	Bindings []iam.Binding
}

type Folder struct {
	types.Metadata
	Folders  []Folder
	Projects []Project
	Members  []iam.Member
	Bindings []iam.Binding
}

type Project struct {
	types.Metadata
	AutoCreateNetwork types.BoolValue
	Members           []iam.Member
	Bindings          []iam.Binding
}


func (p *Platform) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *Platform) GetRawValue() interface{} {
	return nil
}    


func (o *Organization) GetMetadata() *types.Metadata {
	return &o.Metadata
}

func (o *Organization) GetRawValue() interface{} {
	return nil
}    


func (f *Folder) GetMetadata() *types.Metadata {
	return &f.Metadata
}

func (f *Folder) GetRawValue() interface{} {
	return nil
}    


func (p *Project) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *Project) GetRawValue() interface{} {
	return nil
}    

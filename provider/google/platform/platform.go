package platform

import "github.com/aquasecurity/defsec/types"

type Platform struct {
	Projects []Project
	Folders  []Folder
}

type Folder struct {
	Members  []Member
	Bindings []Binding
	Projects []Project
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
}

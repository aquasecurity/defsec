package appmesh

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type AppMesh struct {
	Meshes          []Mesh
	VirtualGateways []VirtualGateway
}

type Mesh struct {
	Metadata defsecTypes.Metadata
	Spec     Spec
}

type VirtualGateway struct {
	Metadata defsecTypes.Metadata
	Spec     VGSpec
}

type Spec struct {
	Metadata     defsecTypes.Metadata
	EgressFilter EgressFilter
}

type EgressFilter struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
}

type VGSpec struct {
	Metadata  defsecTypes.Metadata
	Logging   Logging
	Listeners []Listener
}

type Listener struct {
	Metadata defsecTypes.Metadata
	TLS      TLS
}
type TLS struct {
	Metadata defsecTypes.Metadata
	Mode     defsecTypes.StringValue
}
type Logging struct {
	Metadata  defsecTypes.Metadata
	AccessLog AccessLog
}

type AccessLog struct {
	Metadata defsecTypes.Metadata
	File     File
}

type File struct {
	Metadata defsecTypes.Metadata
	Path     defsecTypes.StringValue
}

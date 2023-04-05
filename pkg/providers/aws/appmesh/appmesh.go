package appmesh

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type AppMesh struct {
	Meshes []Mesh
}

type Mesh struct {
	Metadata        defsecTypes.Metadata
	Name            defsecTypes.StringValue
	Spec            Spec
	VirtualGateways []VirtualGateway
}

type VirtualGateway struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
	MeshName defsecTypes.StringValue
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
	Metadata          defsecTypes.Metadata
	AccessLogFilePath defsecTypes.StringValue
}

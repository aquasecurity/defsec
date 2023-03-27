package appmesh

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/appmesh"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getmeshes(cfFile parser.FileContext) []appmesh.Mesh {
	var meshes []appmesh.Mesh

	meshesResources := cfFile.GetResourcesByType("AWS::AppMesh::Mesh")

	for _, r := range meshesResources {

		mesh := appmesh.Mesh{
			Metadata: r.Metadata(),
			Name:     types.StringDefault("", r.Metadata()),
			Spec: appmesh.Spec{
				Metadata: r.Metadata(),
				EgressFilter: appmesh.EgressFilter{
					Metadata: r.Metadata(),
					Type:     r.GetStringProperty("Spec.EgressFilter.Type"),
				},
			},
			VirtualGateways: getvirtualgateway(cfFile),
		}
		meshes = append(meshes, mesh)
	}
	return meshes
}

func getvirtualgateway(cfFile parser.FileContext) []appmesh.VirtualGateway {
	var VG []appmesh.VirtualGateway

	VGResources := cfFile.GetResourcesByType("AWS::AppMesh::VirtualGateway")

	for _, r := range VGResources {

		VGateway := appmesh.VirtualGateway{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("VirtualGatewayName"),
			MeshName: r.GetStringProperty("MeshName"),
			Spec: appmesh.VGSpec{
				Metadata:  r.Metadata(),
				Listeners: getlisteners(r),
			},
		}
		VG = append(VG, VGateway)
	}
	return VG
}

func getlisteners(r *parser.Resource) (listeners []appmesh.Listener) {
	listener := r.GetProperty("Spec.Listeners")
	for _, list := range listener.AsList() {
		listeners = append(listeners, appmesh.Listener{
			Metadata: list.Metadata(),
			TLS: appmesh.TLS{
				Metadata: list.Metadata(),
				Mode:     list.GetStringProperty("TLS.Mode"),
			},
		})
	}
	return listeners
}

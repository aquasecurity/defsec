package appmesh

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/appmesh"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) appmesh.AppMesh {
	return appmesh.AppMesh{
		Meshes: adaptMeshes(modules),
	}
}

func adaptMeshes(modules terraform.Modules) []appmesh.Mesh {
	var Meshes []appmesh.Mesh
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_appmesh_mesh") {
			Meshes = append(Meshes, adaptMesh(resource, module))
		}
	}
	return Meshes
}

func adaptMesh(resource *terraform.Block, module *terraform.Module) appmesh.Mesh {

	var VG []appmesh.VirtualGateway

	VGReses := module.GetReferencingResources(resource, "aws_appmesh_virtual_gateway", "mesh_name")
	for _, VGRes := range VGReses {
		var listener []appmesh.Listener
		for _, listenerBlock := range VGRes.GetBlocks("listener") {
			listener = append(listener, appmesh.Listener{
				Metadata: listenerBlock.GetMetadata(),
				TLS: appmesh.TLS{
					Metadata: listenerBlock.GetMetadata(),
					Mode:     listenerBlock.GetAttribute("mode").AsStringValueOrDefault("disabled", listenerBlock),
				},
			})

		}

		VG = append(VG, appmesh.VirtualGateway{
			Metadata: VGRes.GetMetadata(),
			Name:     VGRes.GetAttribute("name").AsStringValueOrDefault("", VGRes),
			MeshName: VGRes.GetAttribute("mesh_name").AsStringValueOrDefault("", VGRes),
			Spec: appmesh.VGSpec{
				Metadata:  VGRes.GetMetadata(),
				Listeners: listener,
			},
		})
	}

	mesh := appmesh.Mesh{
		Metadata: resource.GetMetadata(),
		Spec: appmesh.Spec{
			Metadata: resource.GetMetadata(),
			EgressFilter: appmesh.EgressFilter{
				Metadata: resource.GetMetadata(),
				Type:     types.StringDefault("DROP_ALL", resource.GetMetadata()),
			},
		},
		VirtualGateways: VG,
	}

	if specBlock := resource.GetBlock("spec"); specBlock.IsNotNil() {
		mesh.Spec.Metadata = specBlock.GetMetadata()
		if egBlock := specBlock.GetBlock("egress_filter"); egBlock.IsNotNil() {
			mesh.Spec.EgressFilter.Metadata = egBlock.GetMetadata()
			typeAttr := egBlock.GetAttribute("type")
			mesh.Spec.EgressFilter.Type = typeAttr.AsStringValueOrDefault("DROP_ALL", specBlock)
		}
	}

	return mesh
}

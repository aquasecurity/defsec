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
			Meshes = append(Meshes, adaptMesh(resource))
		}
	}
	return Meshes
}

func adaptMesh(resource *terraform.Block) appmesh.Mesh {
	mesh := appmesh.Mesh{
		Metadata: resource.GetMetadata(),
		Spec: appmesh.Spec{
			Metadata: resource.GetMetadata(),
			EgressFilter: appmesh.EgressFilter{
				Metadata: resource.GetMetadata(),
				Type:     types.StringDefault("DROP_ALL", resource.GetMetadata()),
			},
		},
	}

	if specBlock := resource.GetBlock("spec"); specBlock.IsNotNil() {
		mesh.Spec.Metadata = specBlock.GetMetadata()
		if egBlock := resource.GetBlock("egress_filter"); egBlock.IsNotNil() {
			mesh.Spec.EgressFilter.Metadata = egBlock.GetMetadata()
			typeAttr := egBlock.GetAttribute("type")
			mesh.Spec.EgressFilter.Type = typeAttr.AsStringValueOrDefault("DROP_ALL", specBlock)
		}
	}

	return mesh
}

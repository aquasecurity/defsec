package appmesh

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/appmesh"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getmeshes(cfFile parser.FileContext) []appmesh.Mesh {
	var meshes []appmesh.Mesh

	meshesResources := cfFile.GetResourcesByType("AWS::AppMesh::Mesh")

	for _, r := range meshesResources {

		mesh := appmesh.Mesh{
			Metadata: r.Metadata(),
			Spec: appmesh.Spec{
				Metadata: r.Metadata(),
				EgressFilter: appmesh.EgressFilter{
					Metadata: r.Metadata(),
					Type:     r.GetStringProperty("Spec.EgressFilter.Type"),
				},
			},
		}
		meshes = append(meshes, mesh)
	}
	return meshes
}

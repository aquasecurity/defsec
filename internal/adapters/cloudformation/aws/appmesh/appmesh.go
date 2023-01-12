package appmesh

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/appmesh"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) appmesh.AppMesh {
	return appmesh.AppMesh{
		Meshes: getmeshes(cfFile),
	}
}

package imagebuilder

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/imagebuilder"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) imagebuilder.Imagebuilder {
	return imagebuilder.Imagebuilder{
		ContainerRecipes:             getContainerRecipes(cfFile),
		ImagePipelines:               getImagePipelines(cfFile),
		ImageRecipes:                 getImageRecipes(cfFile),
		Components:                   getComponents(cfFile),
		InfrastructureConfigurations: getInfrastructureConfigurations(cfFile),
	}
}

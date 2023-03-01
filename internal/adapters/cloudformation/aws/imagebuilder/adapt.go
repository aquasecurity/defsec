package imagebuilder

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/imagebuilder"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getContainerRecipes(ctx parser.FileContext) []imagebuilder.ContainerRecipe {

	var recipes []imagebuilder.ContainerRecipe

	for _, r := range ctx.GetResourcesByType("AWS::ImageBuilder::ContainerRecipe") {
		recipes = append(recipes, imagebuilder.ContainerRecipe{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("KmsKeyId"),
		})
	}
	return recipes
}

func getImagePipelines(ctx parser.FileContext) []imagebuilder.ImagePipline {
	var pipelines []imagebuilder.ImagePipline
	for _, r := range ctx.GetResourcesByType("AWS::ImageBuilder::ImagePipeline") {
		pipelines = append(pipelines, imagebuilder.ImagePipline{
			Metadata:                     r.Metadata(),
			EnhancedImageMetadataEnabled: r.GetBoolProperty("EnhancedImageMetadataEnabled"),
		})
	}
	return pipelines
}

func getImageRecipes(ctx parser.FileContext) []imagebuilder.ImageRecipe {
	var recipes []imagebuilder.ImageRecipe

	for _, r := range ctx.GetResourcesByType("AWS::ImageBuilder::ImageRecipe") {

		var BDMappings []imagebuilder.BlockDeviceMapping
		for _, m := range r.GetProperty("BlockDeviceMappings").AsList() {
			BDMappings = append(BDMappings, imagebuilder.BlockDeviceMapping{
				Metadata:  m.Metadata(),
				Encrypted: m.GetBoolProperty("Ebs.Encrypted"),
				KmsKeyId:  m.GetStringProperty("Ebs.KmsKeyId"),
			})
		}
		recipes = append(recipes, imagebuilder.ImageRecipe{
			Metadata:            r.Metadata(),
			BlockDeviceMappings: BDMappings,
		})
	}
	return recipes
}

func getComponents(ctx parser.FileContext) []imagebuilder.Component {
	var components []imagebuilder.Component
	for _, r := range ctx.GetResourcesByType("AWS::ImageBuilder::Component") {
		components = append(components, imagebuilder.Component{
			Metadata: r.Metadata(),
			KmsKeyId: r.GetStringProperty("KmsKeyId"),
		})
	}
	return components
}

func getInfrastructureConfigurations(ctx parser.FileContext) []imagebuilder.InfrastructureConfiguration {
	var configurations []imagebuilder.InfrastructureConfiguration

	for _, r := range ctx.GetResourcesByType("AWS::ImageBuilder::InfrastructureConfiguration") {
		configurations = append(configurations, imagebuilder.InfrastructureConfiguration{
			Metadata:    r.Metadata(),
			SnsTopicArn: r.GetStringProperty("SnsTopicArn"),
		})
	}
	return configurations
}

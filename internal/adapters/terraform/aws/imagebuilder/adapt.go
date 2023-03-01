package imagebuilder

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/imagebuilder"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) imagebuilder.Imagebuilder {
	return imagebuilder.Imagebuilder{
		ContainerRecipes:             adaptContainerRecipes(modules),
		Components:                   adaptComponents(modules),
		ImagePipelines:               adaptImagePipelines(modules),
		ImageRecipes:                 adaptImageRecipes(modules),
		InfrastructureConfigurations: adaptInfrastructureConfigurations(modules),
	}
}

func adaptContainerRecipes(modules terraform.Modules) []imagebuilder.ContainerRecipe {
	var recipies []imagebuilder.ContainerRecipe
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_imagebuilder_container_recipe") {
			recipies = append(recipies, imagebuilder.ContainerRecipe{
				Metadata: resource.GetMetadata(),
				KmsKeyId: resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
			})
		}
	}
	return recipies
}

func adaptImagePipelines(modules terraform.Modules) []imagebuilder.ImagePipline {
	var pipelines []imagebuilder.ImagePipline
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_imagebuilder_image_pipeline") {
			pipelines = append(pipelines, imagebuilder.ImagePipline{
				Metadata:                     resource.GetMetadata(),
				EnhancedImageMetadataEnabled: resource.GetAttribute("enhanced_image_metadata_enabled").AsBoolValueOrDefault(true, resource),
			})
		}
	}
	return pipelines
}

func adaptComponents(modules terraform.Modules) []imagebuilder.Component {
	var components []imagebuilder.Component
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_imagebuilder_component") {
			components = append(components, imagebuilder.Component{
				Metadata: resource.GetMetadata(),
				KmsKeyId: resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
			})
		}
	}
	return components
}

func adaptInfrastructureConfigurations(modules terraform.Modules) []imagebuilder.InfrastructureConfiguration {
	var configurations []imagebuilder.InfrastructureConfiguration
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_imagebuilder_infrastructure_configuration") {
			configurations = append(configurations, imagebuilder.InfrastructureConfiguration{
				Metadata:    resource.GetMetadata(),
				SnsTopicArn: resource.GetAttribute("sns_topic_arn").AsStringValueOrDefault("", resource),
			})
		}
	}
	return configurations
}

func adaptImageRecipes(modules terraform.Modules) []imagebuilder.ImageRecipe {
	var recipies []imagebuilder.ImageRecipe
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_imagebuilder_image_recipe") {
			recipies = append(recipies, adaptImageRecipe(resource))
		}
	}
	return recipies
}

func adaptImageRecipe(resource *terraform.Block) imagebuilder.ImageRecipe {
	var BDMapping []imagebuilder.BlockDeviceMapping
	for _, b := range resource.GetBlocks("block_device_mapping") {
		var encrypted types.BoolValue
		var kmskeyid types.StringValue
		if ebsBlock := b.GetBlock("ebs"); ebsBlock.IsNotNil() {
			encrypted = ebsBlock.GetAttribute("encrypted").AsBoolValueOrDefault(false, ebsBlock)
			kmskeyid = ebsBlock.GetAttribute("kms_key_id").AsStringValueOrDefault("", ebsBlock)
		}
		BDMapping = append(BDMapping, imagebuilder.BlockDeviceMapping{
			Metadata:  b.GetMetadata(),
			Encrypted: encrypted,
			KmsKeyId:  kmskeyid,
		})
	}
	return imagebuilder.ImageRecipe{
		Metadata:            resource.GetMetadata(),
		BlockDeviceMappings: BDMapping,
	}
}

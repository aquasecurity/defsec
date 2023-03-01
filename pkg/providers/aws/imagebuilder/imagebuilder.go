package imagebuilder

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Imagebuilder struct {
	ContainerRecipes             []ContainerRecipe
	ImagePipelines               []ImagePipline
	ImageRecipes                 []ImageRecipe
	Components                   []Component
	InfrastructureConfigurations []InfrastructureConfiguration
}

type ContainerRecipe struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

type ImagePipline struct {
	Metadata                     defsecTypes.Metadata
	EnhancedImageMetadataEnabled defsecTypes.BoolValue
}

type ImageRecipe struct {
	Metadata            defsecTypes.Metadata
	BlockDeviceMappings []BlockDeviceMapping
}

type BlockDeviceMapping struct {
	Metadata  defsecTypes.Metadata
	Encrypted defsecTypes.BoolValue
	KmsKeyId  defsecTypes.StringValue
}

type Component struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

type InfrastructureConfiguration struct {
	Metadata    defsecTypes.Metadata
	SnsTopicArn defsecTypes.StringValue
}

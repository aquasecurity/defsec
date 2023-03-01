package imagebuilder

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/imagebuilder"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/imagebuilder"
	"github.com/aws/aws-sdk-go-v2/service/imagebuilder/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "imagebuilder"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ImageBuilder.ContainerRecipes, err = a.getContainerRecipes()
	if err != nil {
		return err
	}

	state.AWS.ImageBuilder.ImagePipelines, err = a.getImagePipelines()
	if err != nil {
		return err
	}

	state.AWS.ImageBuilder.ImageRecipes, err = a.getImageRecipes()
	if err != nil {
		return err
	}

	state.AWS.ImageBuilder.Components, err = a.getComponents()
	if err != nil {
		return err
	}

	state.AWS.ImageBuilder.InfrastructureConfigurations, err = a.getInfrastructureConfigurations()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getContainerRecipes() ([]imagebuilder.ContainerRecipe, error) {

	a.Tracker().SetServiceLabel("Discovering container recipes...")

	var apicontainerrecipes []types.ContainerRecipeSummary
	var input api.ListContainerRecipesInput
	for {
		output, err := a.api.ListContainerRecipes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apicontainerrecipes = append(apicontainerrecipes, output.ContainerRecipeSummaryList...)
		a.Tracker().SetTotalResources(len(apicontainerrecipes))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting container recipes...")
	return concurrency.Adapt(apicontainerrecipes, a.RootAdapter, a.adaptContainerRecipe), nil
}

func (a *adapter) adaptContainerRecipe(container types.ContainerRecipeSummary) (*imagebuilder.ContainerRecipe, error) {

	output, err := a.api.GetContainerRecipe(a.Context(), &api.GetContainerRecipeInput{
		ContainerRecipeArn: container.Arn,
	})
	if err != nil {
		return nil, err
	}
	metadata := a.CreateMetadataFromARN(*container.Arn)

	return &imagebuilder.ContainerRecipe{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(*output.ContainerRecipe.KmsKeyId, metadata),
	}, nil
}

func (a *adapter) getImagePipelines() ([]imagebuilder.ImagePipline, error) {

	a.Tracker().SetServiceLabel("Discovering imagepipelines...")

	var apiimagepipelines []types.ImagePipeline
	var input api.ListImagePipelinesInput
	for {
		output, err := a.api.ListImagePipelines(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiimagepipelines = append(apiimagepipelines, output.ImagePipelineList...)
		a.Tracker().SetTotalResources(len(apiimagepipelines))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting imagepipelines..")
	return concurrency.Adapt(apiimagepipelines, a.RootAdapter, a.adaptImagePipeline), nil
}

func (a *adapter) adaptImagePipeline(pipeline types.ImagePipeline) (*imagebuilder.ImagePipline, error) {
	metadata := a.CreateMetadataFromARN(*pipeline.Arn)

	return &imagebuilder.ImagePipline{
		Metadata:                     metadata,
		EnhancedImageMetadataEnabled: defsecTypes.Bool(*pipeline.EnhancedImageMetadataEnabled, metadata),
	}, nil
}

func (a *adapter) getImageRecipes() ([]imagebuilder.ImageRecipe, error) {

	a.Tracker().SetServiceLabel("Discovering image recipes...")

	var apiimagerecipes []types.ImageRecipeSummary
	var input api.ListImageRecipesInput
	for {
		output, err := a.api.ListImageRecipes(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiimagerecipes = append(apiimagerecipes, output.ImageRecipeSummaryList...)
		a.Tracker().SetTotalResources(len(apiimagerecipes))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting image recipe...")
	return concurrency.Adapt(apiimagerecipes, a.RootAdapter, a.adaptImageRecipe), nil
}

func (a *adapter) adaptImageRecipe(recipe types.ImageRecipeSummary) (*imagebuilder.ImageRecipe, error) {
	metadata := a.CreateMetadataFromARN(*recipe.Arn)

	output, err := a.api.GetImageRecipe(a.Context(), &api.GetImageRecipeInput{
		ImageRecipeArn: recipe.Arn,
	})
	if err != nil {
		return nil, err
	}

	var BDMappings []imagebuilder.BlockDeviceMapping
	for _, mapping := range output.ImageRecipe.BlockDeviceMappings {
		var encrypted bool
		var kmskeyid string
		if mapping.Ebs != nil {
			encrypted = *mapping.Ebs.Encrypted
			kmskeyid = *mapping.Ebs.KmsKeyId
		}
		BDMappings = append(BDMappings, imagebuilder.BlockDeviceMapping{
			Metadata:  metadata,
			Encrypted: defsecTypes.Bool(encrypted, metadata),
			KmsKeyId:  defsecTypes.String(kmskeyid, metadata),
		})
	}

	return &imagebuilder.ImageRecipe{
		Metadata:            metadata,
		BlockDeviceMappings: BDMappings,
	}, nil
}

func (a *adapter) getComponents() ([]imagebuilder.Component, error) {

	a.Tracker().SetServiceLabel("Discovering components...")

	var apicomponents []types.ComponentVersion
	var input api.ListComponentsInput
	for {
		output, err := a.api.ListComponents(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apicomponents = append(apicomponents, output.ComponentVersionList...)
		a.Tracker().SetTotalResources(len(apicomponents))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting components...")
	return concurrency.Adapt(apicomponents, a.RootAdapter, a.adaptComponent), nil
}

func (a *adapter) adaptComponent(component types.ComponentVersion) (*imagebuilder.Component, error) {
	metadata := a.CreateMetadataFromARN(*component.Arn)

	output, err := a.api.GetComponent(a.Context(), &api.GetComponentInput{
		ComponentBuildVersionArn: component.Arn,
	})
	if err != nil {
		return nil, err
	}
	return &imagebuilder.Component{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(*output.Component.KmsKeyId, metadata),
	}, nil
}

func (a *adapter) getInfrastructureConfigurations() ([]imagebuilder.InfrastructureConfiguration, error) {

	a.Tracker().SetServiceLabel("Discovering infrastructure configurations...")

	var apiinfrastructureconfigurations []types.InfrastructureConfigurationSummary
	var input api.ListInfrastructureConfigurationsInput
	for {
		output, err := a.api.ListInfrastructureConfigurations(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiinfrastructureconfigurations = append(apiinfrastructureconfigurations, output.InfrastructureConfigurationSummaryList...)
		a.Tracker().SetTotalResources(len(apiinfrastructureconfigurations))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting infrastructure configurations...")
	return concurrency.Adapt(apiinfrastructureconfigurations, a.RootAdapter, a.adaptInfrastructureConfiguration), nil
}

func (a *adapter) adaptInfrastructureConfiguration(configuration types.InfrastructureConfigurationSummary) (*imagebuilder.InfrastructureConfiguration, error) {
	metadata := a.CreateMetadataFromARN(*configuration.Arn)

	output, err := a.api.GetInfrastructureConfiguration(a.Context(), &api.GetInfrastructureConfigurationInput{
		InfrastructureConfigurationArn: configuration.Arn,
	})
	if err != nil {
		return nil, err
	}

	return &imagebuilder.InfrastructureConfiguration{
		Metadata:    metadata,
		SnsTopicArn: defsecTypes.String(*output.InfrastructureConfiguration.SnsTopicArn, metadata),
	}, nil
}

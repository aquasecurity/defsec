package codebuild

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codebuild"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) codebuild.CodeBuild {
	return codebuild.CodeBuild{
		Projects: adaptProjects(modules),
	}
}

func adaptProjects(modules terraform.Modules) []codebuild.Project {
	var projects []codebuild.Project
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_codebuild_project") {
			projects = append(projects, adaptProject(resource))
		}
	}
	return projects
}

func adaptProject(resource *terraform.Block) codebuild.Project {

	project := codebuild.Project{
		Metadata:      resource.GetMetadata(),
		SourceType:    types.StringDefault("", resource.GetMetadata()),
		EncryptionKey: resource.GetAttribute("encryption_key").AsStringValueOrDefault("", resource),
		ArtifactSettings: codebuild.ArtifactSettings{
			Metadata:          resource.GetMetadata(),
			EncryptionEnabled: types.BoolDefault(true, resource.GetMetadata()),
		},
		SecondaryArtifactSettings: nil,
		SecondarySources:          nil,
	}

	if sourceblock := resource.GetBlock("source"); sourceblock.IsNotNil() {
		project.SourceType = sourceblock.GetAttribute("type").AsStringValueOrDefault("CODECOMMIT", sourceblock)
	}

	var hasArtifacts bool

	if artifactsBlock := resource.GetBlock("artifacts"); artifactsBlock.IsNotNil() {
		project.ArtifactSettings.Metadata = artifactsBlock.GetMetadata()
		typeAttr := artifactsBlock.GetAttribute("type")
		encryptionDisabledAttr := artifactsBlock.GetAttribute("encryption_disabled")
		hasArtifacts = typeAttr.NotEqual("NO_ARTIFACTS")
		if encryptionDisabledAttr.IsTrue() && hasArtifacts {
			project.ArtifactSettings.EncryptionEnabled = types.Bool(false, artifactsBlock.GetMetadata())
		} else {
			project.ArtifactSettings.EncryptionEnabled = types.Bool(true, artifactsBlock.GetMetadata())
		}
	}

	secondaryArtifactBlocks := resource.GetBlocks("secondary_artifacts")
	for _, secondaryArtifactBlock := range secondaryArtifactBlocks {

		secondaryEncryptionEnabled := types.BoolDefault(true, secondaryArtifactBlock.GetMetadata())
		secondaryEncryptionDisabledAttr := secondaryArtifactBlock.GetAttribute("encryption_disabled")
		if secondaryEncryptionDisabledAttr.IsTrue() && hasArtifacts {
			secondaryEncryptionEnabled = types.Bool(false, secondaryArtifactBlock.GetMetadata())
		}

		project.SecondaryArtifactSettings = append(project.SecondaryArtifactSettings, codebuild.ArtifactSettings{
			Metadata:          secondaryArtifactBlock.GetMetadata(),
			EncryptionEnabled: secondaryEncryptionEnabled,
		})
	}

	secondrysources := resource.GetBlocks("secondary_sources")
	for _, ss := range secondrysources {
		project.SecondarySources = append(project.SecondarySources, codebuild.SecondarySources{
			Metadata: ss.GetMetadata(),
			Type:     ss.GetAttribute("type").AsStringValueOrDefault("CODECOMMIT", ss),
		})
	}

	return project
}

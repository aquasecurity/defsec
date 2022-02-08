package codebuild

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/codebuild"
	"github.com/aquasecurity/defsec/types"
)

func getProjects(ctx parser.FileContext) (projects []codebuild.Project) {

	projectResources := ctx.GetResourceByType("AWS::CodeBuild::Project")

	for _, r := range projectResources {
		project := codebuild.Project{
			Metadata:                  r.Metadata(),
			ArtifactSettings:          getArtifactSettings(r),
			SecondaryArtifactSettings: getSecondaryArtifactSettings(r),
		}

		projects = append(projects, project)
	}

	return projects
}

func getSecondaryArtifactSettings(r *parser.Resource) (secondaryArtifacts []codebuild.ArtifactSettings) {
	secondaryArtifactsList := r.GetProperty("SecondaryArtifacts")
	if secondaryArtifactsList.IsNil() || !secondaryArtifactsList.IsList() {
		return
	}

	for _, a := range secondaryArtifactsList.AsList() {
		secondaryArtifacts = append(secondaryArtifacts, getSetting(a))
	}

	return secondaryArtifacts
}

func getArtifactSettings(r *parser.Resource) (artifactSettings codebuild.ArtifactSettings) {
	artifactsProperty := r.GetProperty("Artifacts")
	if artifactsProperty.IsNil() {
		return
	}
	return getSetting(artifactsProperty)
}

func getSetting(property *parser.Property) codebuild.ArtifactSettings {
	result := types.BoolDefault(true, property.Metadata())
	encryptionDisabled := property.GetProperty("EncryptionDisabled")
	if encryptionDisabled.IsBool() {
		result = types.Bool(!encryptionDisabled.AsBool(), encryptionDisabled.Metadata())
	}

	return codebuild.ArtifactSettings{
		Metadata:          property.Metadata(),
		EncryptionEnabled: result,
	}
}

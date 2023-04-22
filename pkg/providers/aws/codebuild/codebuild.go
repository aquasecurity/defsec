package codebuild

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	Metadata                  defsecTypes.Metadata
	SourceType                defsecTypes.StringValue
	EncryptionKey             defsecTypes.StringValue
	SecondarySources          []SecondarySources
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	Metadata          defsecTypes.Metadata
	EncryptionEnabled defsecTypes.BoolValue
}

type SecondarySources struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
}

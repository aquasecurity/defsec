package codebuild

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	defsecTypes.Metadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	defsecTypes.Metadata
	EncryptionEnabled defsecTypes.BoolValue
}

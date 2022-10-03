package codebuild

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	Metadata                  defsecTypes.Metadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	Metadata          defsecTypes.Metadata
	EncryptionEnabled defsecTypes.BoolValue
}

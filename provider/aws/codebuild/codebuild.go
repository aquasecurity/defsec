package codebuild

import "github.com/aquasecurity/defsec/types"

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings ArtifactSettings
}

type ArtifactSettings struct {
	EncryptionEnabled types.BoolValue
}

package codebuild

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	types2.Metadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	types2.Metadata
	EncryptionEnabled types2.BoolValue
}

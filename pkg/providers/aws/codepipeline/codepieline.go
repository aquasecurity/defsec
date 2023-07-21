package codepipeline

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Codepipeline struct {
	Pipelines []Pipeline
}

type Pipeline struct {
	Metadata      defsecTypes.Metadata
	EncryptionKey defsecTypes.StringValue
}

package elastictranscoder

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ElasticTranscoder struct {
	Pipelines []Pipeline
}

type Pipeline struct {
	Metadata     defsecTypes.Metadata
	AwsKmsKeyArn defsecTypes.StringValue
	Status       defsecTypes.StringValue
	Outputs      []Output
}

type Output struct {
	Metadata   defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Key      defsecTypes.StringValue
}

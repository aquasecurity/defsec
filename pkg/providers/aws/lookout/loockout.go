package lookout

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Lookout struct {
	AnomalyDetectors []AnomalyDetector
	Models           []Model
	Datasets         []Dataset
}

type AnomalyDetector struct {
	Metadata  defsecTypes.Metadata
	KmsKeyArn defsecTypes.StringValue
}

type Model struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

type Dataset struct {
	Metadata           defsecTypes.Metadata
	ServerSideKmsKeyId defsecTypes.StringValue
}

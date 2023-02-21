package wisdom

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Wisdom struct {
	Assistants []Assistant
}

type Assistant struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

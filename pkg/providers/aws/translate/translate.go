package translate

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Translate struct {
	ListTextTranslateJobs []ListJob
}

type ListJob struct {
	Metadata        defsecTypes.Metadata
	JobName         defsecTypes.StringValue
	EncryptionkeyId defsecTypes.StringValue
}

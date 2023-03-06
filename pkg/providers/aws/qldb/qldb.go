package qldb

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Translate struct {
	ListTextTranslateJobs []ListJob
}

type ListJob struct {
	Metadata defsecTypes.Metadata
}

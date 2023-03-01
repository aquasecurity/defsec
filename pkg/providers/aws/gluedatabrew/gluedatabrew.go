package gluedatabrew

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type GlueDataBrew struct {
	Jobs []Job
}

type Job struct {
	Metadata         defsecTypes.Metadata
	EncryptionMode   defsecTypes.StringValue
	EncryptionKeyArn defsecTypes.StringValue
}

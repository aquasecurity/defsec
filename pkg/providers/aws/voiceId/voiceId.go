package voiceid

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type VoiceId struct {
	Domains []Domain
}

type Domain struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}

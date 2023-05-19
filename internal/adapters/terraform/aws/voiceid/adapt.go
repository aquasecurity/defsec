package voiceid

import (
	voiceid "github.com/aquasecurity/defsec/pkg/providers/aws/voiceId"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) voiceid.VoiceId {
	return voiceid.VoiceId{
		Domains: nil,
	}
}

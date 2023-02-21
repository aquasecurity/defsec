package voiceid

import (
	voiceid "github.com/aquasecurity/defsec/pkg/providers/aws/voiceId"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) voiceid.VoiceId {
	return voiceid.VoiceId{
		Domains: getDomain(cfFile),
	}
}

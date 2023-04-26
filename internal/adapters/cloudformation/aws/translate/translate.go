package translate

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/translate"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) translate.Translate {
	return translate.Translate{
		ListTextTranslateJobs: nil,
	}
}

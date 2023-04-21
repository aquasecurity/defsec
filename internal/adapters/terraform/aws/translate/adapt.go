package translate

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/translate"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) translate.Translate {
	return translate.Translate{
		ListTextTranslateJobs: nil,
	}
}

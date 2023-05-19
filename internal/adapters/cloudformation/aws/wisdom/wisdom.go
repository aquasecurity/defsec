package wisdom

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/wisdom"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) wisdom.Wisdom {
	return wisdom.Wisdom{
		Assistants: getAssistant(cfFile),
	}
}

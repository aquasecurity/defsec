package wisdom

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/wisdom"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) wisdom.Wisdom {
	return wisdom.Wisdom{
		Assistants: nil,
	}
}

package external

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/external/sources"
	"github.com/aquasecurity/defsec/pkg/providers/external"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) external.External {
	return external.External{
		Sources: sources.Adapt(modules),
	}
}

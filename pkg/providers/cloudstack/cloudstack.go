package cloudstack

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/cloudstack/compute"
)

type CloudStack struct {
	types.Metadata
	Compute compute.Compute
}

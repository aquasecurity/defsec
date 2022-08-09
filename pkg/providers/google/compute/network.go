package compute

import (
	"github.com/aquasecurity/defsec/pkg/types"
)

type Network struct {
	types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}

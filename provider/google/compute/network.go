package compute

import "github.com/aquasecurity/defsec/definition"

type Network struct {
	*definition.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}

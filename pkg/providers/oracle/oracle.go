package oracle

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Oracle struct {
	Compute Compute
}

type Compute struct {
	AddressReservations []AddressReservation
}

type AddressReservation struct {
	types2.Metadata
	Pool types2.StringValue // e.g. public-pool
}

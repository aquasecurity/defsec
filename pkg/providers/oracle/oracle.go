package oracle

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Oracle struct {
	Compute Compute
}

type Compute struct {
	AddressReservations []AddressReservation
}

type AddressReservation struct {
	defsecTypes.Metadata
	Pool defsecTypes.StringValue // e.g. public-pool
}

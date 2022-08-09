package dns

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type DNS struct {
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	defsecTypes.Metadata
	DNSSec     DNSSec
	Visibility defsecTypes.StringValue
}

func (m ManagedZone) IsPrivate() bool {
	return m.Visibility.EqualTo("private", defsecTypes.IgnoreCase)
}

type DNSSec struct {
	defsecTypes.Metadata
	Enabled         defsecTypes.BoolValue
	DefaultKeySpecs KeySpecs
}

type KeySpecs struct {
	defsecTypes.Metadata
	KeySigningKey  Key
	ZoneSigningKey Key
}

type Key struct {
	defsecTypes.Metadata
	Algorithm defsecTypes.StringValue
}

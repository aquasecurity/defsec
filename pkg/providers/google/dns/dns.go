package dns

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type DNS struct {
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	types2.Metadata
	DNSSec     DNSSec
	Visibility types2.StringValue
}

func (m ManagedZone) IsPrivate() bool {
	return m.Visibility.EqualTo("private", types2.IgnoreCase)
}

type DNSSec struct {
	types2.Metadata
	Enabled         types2.BoolValue
	DefaultKeySpecs KeySpecs
}

type KeySpecs struct {
	types2.Metadata
	KeySigningKey  Key
	ZoneSigningKey Key
}

type Key struct {
	types2.Metadata
	Algorithm types2.StringValue
}

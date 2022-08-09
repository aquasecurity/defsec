package storage

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Storage struct {
	Accounts []Account
}

type Account struct {
	defsecTypes.Metadata
	NetworkRules      []NetworkRule
	EnforceHTTPS      defsecTypes.BoolValue
	Containers        []Container
	QueueProperties   QueueProperties
	MinimumTLSVersion defsecTypes.StringValue
}

type QueueProperties struct {
	defsecTypes.Metadata
	EnableLogging defsecTypes.BoolValue
}

type NetworkRule struct {
	defsecTypes.Metadata
	Bypass         []defsecTypes.StringValue
	AllowByDefault defsecTypes.BoolValue
}

const (
	PublicAccessOff       = "off"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"
)

type Container struct {
	defsecTypes.Metadata
	PublicAccess defsecTypes.StringValue
}

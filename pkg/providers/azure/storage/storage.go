package storage

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Storage struct {
	Accounts []Account
}

type Account struct {
	types2.Metadata
	NetworkRules      []NetworkRule
	EnforceHTTPS      types2.BoolValue
	Containers        []Container
	QueueProperties   QueueProperties
	MinimumTLSVersion types2.StringValue
}

type QueueProperties struct {
	types2.Metadata
	EnableLogging types2.BoolValue
}

type NetworkRule struct {
	types2.Metadata
	Bypass         []types2.StringValue
	AllowByDefault types2.BoolValue
}

const (
	PublicAccessOff       = "off"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"
)

type Container struct {
	types2.Metadata
	PublicAccess types2.StringValue
}

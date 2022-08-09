package elasticsearch

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Elasticsearch struct {
	Domains []Domain
}

type Domain struct {
	defsecTypes.Metadata
	DomainName        defsecTypes.StringValue
	LogPublishing     LogPublishing
	TransitEncryption TransitEncryption
	AtRestEncryption  AtRestEncryption
	Endpoint          Endpoint
}

type Endpoint struct {
	defsecTypes.Metadata
	EnforceHTTPS defsecTypes.BoolValue
	TLSPolicy    defsecTypes.StringValue
}

type LogPublishing struct {
	defsecTypes.Metadata
	AuditEnabled defsecTypes.BoolValue
}

type TransitEncryption struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type AtRestEncryption struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

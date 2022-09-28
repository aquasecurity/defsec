package elasticsearch

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Elasticsearch struct {
	Domains []Domain
}

type Domain struct {
	Metadata          defsecTypes.Metadata
	DomainName        defsecTypes.StringValue
	LogPublishing     LogPublishing
	TransitEncryption TransitEncryption
	AtRestEncryption  AtRestEncryption
	Endpoint          Endpoint
}

type Endpoint struct {
	Metadata     defsecTypes.Metadata
	EnforceHTTPS defsecTypes.BoolValue
	TLSPolicy    defsecTypes.StringValue
}

type LogPublishing struct {
	Metadata     defsecTypes.Metadata
	AuditEnabled defsecTypes.BoolValue
}

type TransitEncryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type AtRestEncryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

package elasticsearch

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Elasticsearch struct {
	Domains []Domain
}

type Domain struct {
	types2.Metadata
	DomainName        types2.StringValue
	LogPublishing     LogPublishing
	TransitEncryption TransitEncryption
	AtRestEncryption  AtRestEncryption
	Endpoint          Endpoint
}

type Endpoint struct {
	types2.Metadata
	EnforceHTTPS types2.BoolValue
	TLSPolicy    types2.StringValue
}

type LogPublishing struct {
	types2.Metadata
	AuditEnabled types2.BoolValue
}

type TransitEncryption struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type AtRestEncryption struct {
	types2.Metadata
	Enabled types2.BoolValue
}

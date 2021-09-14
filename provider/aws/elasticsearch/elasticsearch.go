package elasticsearch

import "github.com/aquasecurity/defsec/types"

type Elasticsearch struct {
	Domains           []Domain
	ReplicationGroups []ReplicationGroup
}

type Domain struct {
	types.Metadata
	DomainName        types.StringValue
	LogPublishing     LogPublishing
	TransitEncryption TransitEncryption
	AtRestEncryption  AtRestEncryption
	Endpoint          Endpoint
}

type Endpoint struct {
	EnforceHTTPS types.BoolValue
	TLSPolicy    types.StringValue
}

type LogPublishing struct {
	AuditEnabled types.BoolValue
}

type TransitEncryption struct {
	Enabled types.BoolValue
}

type ReplicationGroup struct {
	types.Metadata
	AtRestEncryption AtRestEncryption
}

type AtRestEncryption struct {
	Enabled types.BoolValue
}

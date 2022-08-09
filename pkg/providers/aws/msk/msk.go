package msk

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	types2.Metadata
	EncryptionInTransit EncryptionInTransit
	Logging             Logging
}

const (
	ClientBrokerEncryptionTLS            = "TLS"
	ClientBrokerEncryptionPlaintext      = "PLAINTEXT"
	ClientBrokerEncryptionTLSOrPlaintext = "TLS_PLAINTEXT"
)

type EncryptionInTransit struct {
	types2.Metadata
	ClientBroker types2.StringValue
}

type Logging struct {
	types2.Metadata
	Broker BrokerLogging
}

type BrokerLogging struct {
	types2.Metadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type CloudwatchLogging struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type FirehoseLogging struct {
	types2.Metadata
	Enabled types2.BoolValue
}

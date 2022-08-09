package msk

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	defsecTypes.Metadata
	EncryptionInTransit EncryptionInTransit
	Logging             Logging
}

const (
	ClientBrokerEncryptionTLS            = "TLS"
	ClientBrokerEncryptionPlaintext      = "PLAINTEXT"
	ClientBrokerEncryptionTLSOrPlaintext = "TLS_PLAINTEXT"
)

type EncryptionInTransit struct {
	defsecTypes.Metadata
	ClientBroker defsecTypes.StringValue
}

type Logging struct {
	defsecTypes.Metadata
	Broker BrokerLogging
}

type BrokerLogging struct {
	defsecTypes.Metadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type CloudwatchLogging struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type FirehoseLogging struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

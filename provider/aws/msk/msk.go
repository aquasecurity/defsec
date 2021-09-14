package msk

import "github.com/aquasecurity/defsec/types"

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	EncryptionInTransit EncryptionInTransit
	Logging             Logging
}

const (
	ClientBrokerEncryptionPlaintext      = "PLAINTEXT"
	ClientBrokerEncryptionTLSOrPlaintext = "TLS_PLAINTEXT"
)

type EncryptionInTransit struct {
	ClientBroker types.StringValue
}

type Logging struct {
	Broker BrokerLogging
}

type BrokerLogging struct {
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	Enabled types.BoolValue
}

type CloudwatchLogging struct {
	Enabled types.BoolValue
}

type FirehoseLogging struct {
	Enabled types.BoolValue
}

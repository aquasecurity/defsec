package msk

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type MSK struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata             defsecTypes.Metadata
	EncryptionInTransit  EncryptionInTransit
	EncryptionAtRest     EncryptionAtRest
	BrokerNodeGroupInfo  BrokerNodeGroupInfo
	ClientAuthentication ClientAuthentication
	Logging              Logging
}

const (
	ClientBrokerEncryptionTLS            = "TLS"
	ClientBrokerEncryptionPlaintext      = "PLAINTEXT"
	ClientBrokerEncryptionTLSOrPlaintext = "TLS_PLAINTEXT"
)

type EncryptionInTransit struct {
	Metadata     defsecTypes.Metadata
	ClientBroker defsecTypes.StringValue
	InCluster    defsecTypes.BoolValue
}

type EncryptionAtRest struct {
	Metadata  defsecTypes.Metadata
	KMSKeyARN defsecTypes.StringValue
	Enabled   defsecTypes.BoolValue
}

type Logging struct {
	Metadata defsecTypes.Metadata
	Broker   BrokerLogging
}

type BrokerLogging struct {
	Metadata   defsecTypes.Metadata
	S3         S3Logging
	Cloudwatch CloudwatchLogging
	Firehose   FirehoseLogging
}

type S3Logging struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type CloudwatchLogging struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type FirehoseLogging struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type BrokerNodeGroupInfo struct {
	Metadata         defsecTypes.Metadata
	PublicAccessType defsecTypes.StringValue
}

type ClientAuthentication struct {
	Metadata        defsecTypes.Metadata
	Unauthenticated defsecTypes.BoolValue
}

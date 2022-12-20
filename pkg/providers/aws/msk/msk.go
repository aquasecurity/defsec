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
	Logging              Logging
	ClientAuthentication ClientAuthentication
	BrokerNodeGroupInfo  BrokerNodeGroupInfo
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

type ClientAuthentication struct {
	Metadata        defsecTypes.Metadata
	Unauthenticated Unauthenticated
}

type Unauthenticated struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type BrokerNodeGroupInfo struct {
	Metadata         defsecTypes.Metadata
	ConnectivityInfo ConnectivityInfo
}

type ConnectivityInfo struct {
	Metadata     defsecTypes.Metadata
	PublicAccess PublicAccess
}

type PublicAccess struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
}

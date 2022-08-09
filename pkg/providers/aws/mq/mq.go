package mq

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type MQ struct {
	Brokers []Broker
}

type Broker struct {
	types2.Metadata
	PublicAccess types2.BoolValue
	Logging      Logging
}

type Logging struct {
	types2.Metadata
	General types2.BoolValue
	Audit   types2.BoolValue
}

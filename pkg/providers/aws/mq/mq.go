package mq

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type MQ struct {
	Brokers []Broker
}

type Broker struct {
	Metadata                defsecTypes.Metadata
	PublicAccess            defsecTypes.BoolValue
	DeploymentMode          defsecTypes.StringValue
	EngineType              defsecTypes.StringValue
	HostInstanceType        defsecTypes.StringValue
	KmsKeyId                defsecTypes.StringValue
	AutoMinorVersionUpgrade defsecTypes.BoolValue
	Logging                 Logging
}

type Logging struct {
	Metadata defsecTypes.Metadata
	General  defsecTypes.BoolValue
	Audit    defsecTypes.BoolValue
}

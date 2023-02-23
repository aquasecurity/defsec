package elasticbeanstalk

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ElasticBeanStalk struct {
	Environments []Environment
}

type Environment struct {
	Metadata       defsecTypes.Metadata
	HealthStatus   defsecTypes.StringValue
	OptionSettings []OptionSetting
}

type OptionSetting struct {
	Metadata   defsecTypes.Metadata
	NameSpace  defsecTypes.StringValue
	OptionName defsecTypes.StringValue
	Value      defsecTypes.StringValue
}

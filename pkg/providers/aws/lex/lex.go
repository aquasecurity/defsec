package lex

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Lex struct {
	BotAliases []BotAlias
}

type BotAlias struct {
	Metadata         defsecTypes.Metadata
	AudioLogSettings []AudioLogSetting
}

type AudioLogSetting struct {
	Metadata  defsecTypes.Metadata
	KmsKeyArn defsecTypes.StringValue
}

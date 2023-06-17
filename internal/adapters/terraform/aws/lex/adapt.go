package lex

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lex"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) lex.Lex {
	return lex.Lex{
		BotAliases: adaptBotAliases(modules),
	}
}

func adaptBotAliases(modules terraform.Modules) []lex.BotAlias {
	var botAliases []lex.BotAlias
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_lex_bot_alias") {
			botAliases = append(botAliases, adaptBotAlias(resource, module))
		}
	}
	return botAliases
}

func adaptBotAlias(resource *terraform.Block, module *terraform.Module) lex.BotAlias {

	var logsettings []lex.AudioLogSetting
	if logBlock := resource.GetBlock("conversation_logs"); logBlock.IsNotNil() {
		for _, ls := range logBlock.GetBlocks("log_settings") {
			logsettings = append(logsettings, lex.AudioLogSetting{
				Metadata:  ls.GetMetadata(),
				KmsKeyArn: ls.GetAttribute("kms_key_arn").AsStringValueOrDefault("", ls),
			})
		}
	}
	return lex.BotAlias{
		Metadata:         resource.GetMetadata(),
		AudioLogSettings: logsettings,
	}

}

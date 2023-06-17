package lex

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lex"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getBotAlias(ctx parser.FileContext) []lex.BotAlias {
	var botaliases []lex.BotAlias

	for _, r := range ctx.GetResourcesByType("AWS::Lex::BotAlias") {

		var logsettings []lex.AudioLogSetting
		for _, al := range r.GetProperty("ConversationLogSettings.AudioLogSettings").AsList() {
			logsettings = append(logsettings, lex.AudioLogSetting{
				Metadata:  al.Metadata(),
				KmsKeyArn: al.GetStringProperty("Destination.S3Bucket.KmsKeyArn"),
			})
		}
		botaliases = append(botaliases, lex.BotAlias{
			Metadata:         r.Metadata(),
			AudioLogSettings: logsettings,
		})

	}
	return botaliases
}

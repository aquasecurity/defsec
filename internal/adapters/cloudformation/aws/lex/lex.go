package lex

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lex"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) lex.Lex {
	return lex.Lex{
		BotAliases: getBotAlias(cfFile),
	}
}

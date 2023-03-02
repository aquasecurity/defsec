package lex

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/lex"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/lexmodelsv2"
	"github.com/aws/aws-sdk-go-v2/service/lexmodelsv2/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "lex"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Lex.BotAliases, err = a.getBotAliases()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getBotAliases() ([]lex.BotAlias, error) {

	a.Tracker().SetServiceLabel("Discovering botAliases...")

	var apibots []types.BotAliasSummary
	var input api.ListBotsInput
	output, err := a.api.ListBots(a.Context(), &input)
	if err != nil {
		return nil, err
	}
	for _, bot := range output.BotSummaries {
		alias, err := a.api.ListBotAliases(a.Context(), &api.ListBotAliasesInput{
			BotId: bot.BotId,
		})
		if err != nil {
			return nil, err
		}

		apibots = append(apibots, alias.BotAliasSummaries...)
		a.Tracker().SetTotalResources(len(apibots))
		if alias.NextToken == nil {
			break
		}
		input.NextToken = alias.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting botAlias...")
	return concurrency.Adapt(apibots, a.RootAdapter, a.adaptBotAlias), nil
}

func (a *adapter) adaptBotAlias(alias types.BotAliasSummary) (*lex.BotAlias, error) {

	metadata := a.CreateMetadata(*alias.BotAliasId)

	output, err := a.api.DescribeBotAlias(a.Context(), &api.DescribeBotAliasInput{
		BotAliasId: alias.BotAliasId,
	})
	if err != nil {
		return nil, err
	}
	var logsettings []lex.AudioLogSetting
	if output.ConversationLogSettings != nil {
		for _, ls := range output.ConversationLogSettings.AudioLogSettings {
			var kmskeyarn string
			if ls.Destination != nil && ls.Destination.S3Bucket != nil {
				kmskeyarn = *ls.Destination.S3Bucket.KmsKeyArn
			}
			logsettings = append(logsettings, lex.AudioLogSetting{
				Metadata:  metadata,
				KmsKeyArn: defsecTypes.String(kmskeyarn, metadata),
			})
		}
	}
	return &lex.BotAlias{
		Metadata:         metadata,
		AudioLogSettings: logsettings,
	}, nil
}

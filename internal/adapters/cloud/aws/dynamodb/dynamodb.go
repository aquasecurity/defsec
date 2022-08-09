package dynamodb

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/state"
	types2 "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	dynamodbApi "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type adapter struct {
	*aws2.RootAdapter
	api *dynamodbApi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a adapter) Name() string {
	return "dynamodb"
}

func (a adapter) Provider() string {
	return "aws"
}

func (a adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {
	a.RootAdapter = root
	a.api = dynamodbApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.DynamoDB.Tables, err = a.getTables()
	if err != nil {
		return err
	}

	return nil
}

func (a adapter) getTables() (tables []dynamodb.Table, err error) {

	a.Tracker().SetServiceLabel("Scanning DynamoDB tables...")

	batchTables, token, err := a.getTableBatch(nil)
	if err != nil {
		return tables, err
	}
	tables = append(tables, batchTables...)

	for token != nil {
		batchTables, token, err = a.getTableBatch(nil)
		if err != nil {
			return tables, err
		}
		tables = append(tables, batchTables...)
	}

	return tables, nil
}

func (a *adapter) getTableBatch(token *string) (tables []dynamodb.Table, nextToken *string, err error) {

	input := dynamodbApi.ListTablesInput{}

	if token != nil {
		input.ExclusiveStartTableName = token
	}

	apiTables, err := a.api.ListTables(a.Context(), &input)
	if err != nil {
		return tables, nil, err
	}

	for _, apiTable := range apiTables.TableNames {

		tableMetadata := a.CreateMetadata(apiTable)

		table, err := a.api.DescribeTable(a.Context(), &dynamodbApi.DescribeTableInput{
			TableName: aws.String(apiTable),
		})
		if err != nil {
			a.Debug("Failed to adapt table '%s': %s", apiTable, err)
			continue
		}

		encryption := dynamodb.ServerSideEncryption{
			Metadata: tableMetadata,
			Enabled:  types2.BoolDefault(false, tableMetadata),
			KMSKeyID: types2.StringDefault("", tableMetadata),
		}

		if table.Table.SSEDescription != nil {

			if table.Table.SSEDescription.Status == dynamodbTypes.SSEStatusEnabled {
				encryption.Enabled = types2.BoolDefault(true, tableMetadata)
			}

			if table.Table.SSEDescription.KMSMasterKeyArn != nil {
				encryption.KMSKeyID = types2.StringDefault(*table.Table.SSEDescription.KMSMasterKeyArn, tableMetadata)
			}
		}

		pitRecovery := types2.Bool(false, tableMetadata)
		continuousBackup, err := a.api.DescribeContinuousBackups(a.Context(), &dynamodbApi.DescribeContinuousBackupsInput{
			TableName: aws.String(apiTable),
		})

		if err != nil && continuousBackup != nil && continuousBackup.ContinuousBackupsDescription != nil && continuousBackup.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
			if continuousBackup.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dynamodbTypes.PointInTimeRecoveryStatusEnabled {
				pitRecovery = types2.BoolDefault(true, tableMetadata)
			}

		}

		tables = append(tables, dynamodb.Table{
			Metadata:             tableMetadata,
			ServerSideEncryption: encryption,
			PointInTimeRecovery:  pitRecovery,
		})

		a.Tracker().IncrementResource()
	}

	return tables, apiTables.LastEvaluatedTableName, nil
}

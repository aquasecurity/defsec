package dynamodb

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	dynamodbApi "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type adapter struct {
	*aws2.RootAdapter
	client *dynamodbApi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Name() string {
	return "dynamodb"
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {
	a.RootAdapter = root
	a.client = dynamodbApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.DynamoDB.Tables, err = a.getTables()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getTables() (tables []dynamodb.Table, err error) {

	a.Tracker().SetServiceLabel("Discovering DynamoDB tables...")

	var apiTables []string
	var input dynamodbApi.ListTablesInput
	for {
		output, err := a.client.ListTables(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiTables = append(apiTables, output.TableNames...)
		a.Tracker().SetTotalResources(len(apiTables))
		if output.LastEvaluatedTableName == nil {
			break
		}
		input.ExclusiveStartTableName = output.LastEvaluatedTableName
	}

	a.Tracker().SetServiceLabel("Adapting DynamoDB tables...")
	return concurrency.Adapt(apiTables, a.RootAdapter, a.adaptTable), nil

}

func (a *adapter) adaptTable(tableName string) (*dynamodb.Table, error) {

	tableMetadata := a.CreateMetadata(tableName)

	table, err := a.client.DescribeTable(a.Context(), &dynamodbApi.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return nil, err
	}
	encryption := dynamodb.ServerSideEncryption{
		Metadata: tableMetadata,
		Enabled:  defsecTypes.BoolDefault(false, tableMetadata),
		KMSKeyID: defsecTypes.StringDefault("", tableMetadata),
	}
	if table.Table.SSEDescription != nil {

		if table.Table.SSEDescription.Status == dynamodbTypes.SSEStatusEnabled {
			encryption.Enabled = defsecTypes.BoolDefault(true, tableMetadata)
		}

		if table.Table.SSEDescription.KMSMasterKeyArn != nil {
			encryption.KMSKeyID = defsecTypes.StringDefault(*table.Table.SSEDescription.KMSMasterKeyArn, tableMetadata)
		}
	}
	pitRecovery := defsecTypes.Bool(false, tableMetadata)
	continuousBackup, err := a.client.DescribeContinuousBackups(a.Context(), &dynamodbApi.DescribeContinuousBackupsInput{
		TableName: aws.String(tableName),
	})

	if err != nil && continuousBackup != nil && continuousBackup.ContinuousBackupsDescription != nil &&
		continuousBackup.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
		if continuousBackup.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dynamodbTypes.PointInTimeRecoveryStatusEnabled {
			pitRecovery = defsecTypes.BoolDefault(true, tableMetadata)
		}

	}
	return &dynamodb.Table{
		Metadata:             tableMetadata,
		ServerSideEncryption: encryption,
		PointInTimeRecovery:  pitRecovery,
	}, nil
}

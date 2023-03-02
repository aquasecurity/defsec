package dynamodb

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	daxApi "github.com/aws/aws-sdk-go-v2/service/dax"
	daxtype "github.com/aws/aws-sdk-go-v2/service/dax/types"
	dynamodbApi "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type adapter struct {
	*aws2.RootAdapter
	client  *dynamodbApi.Client
	client2 *daxApi.Client
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

	state.AWS.DynamoDB.Backups, err = a.getBackups()
	if err != nil {
		return err
	}

	state.AWS.DynamoDB.DAXClusters, err = a.getcluster()
	if err == nil {
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
	var status string
	if err != nil && continuousBackup != nil && continuousBackup.ContinuousBackupsDescription != nil &&
		continuousBackup.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
		if continuousBackup.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == dynamodbTypes.PointInTimeRecoveryStatusEnabled {
			pitRecovery = defsecTypes.BoolDefault(true, tableMetadata)
		}
		status = string(continuousBackup.ContinuousBackupsDescription.ContinuousBackupsStatus)

	}
	return &dynamodb.Table{
		Metadata:               tableMetadata,
		ServerSideEncryption:   encryption,
		PointInTimeRecovery:    pitRecovery,
		ContinuousBackupStatus: defsecTypes.String(status, tableMetadata),
	}, nil
}

func (a *adapter) getBackups() (Backup []dynamodb.Backup, err error) {

	a.Tracker().SetServiceLabel("Discovering DynamoDB backups...")

	var apiBackup []dynamodbTypes.BackupSummary
	var input dynamodbApi.ListBackupsInput
	for {
		output, err := a.client.ListBackups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiBackup = append(apiBackup, output.BackupSummaries...)
		a.Tracker().SetTotalResources(len(apiBackup))
		if output.LastEvaluatedBackupArn == nil {
			break
		}

	}

	a.Tracker().SetServiceLabel("Adapting DynamoDB backups..")
	return concurrency.Adapt(apiBackup, a.RootAdapter, a.adaptbackup), nil

}

func (a *adapter) adaptbackup(backup dynamodbTypes.BackupSummary) (*dynamodb.Backup, error) {

	metadata := a.CreateMetadataFromARN(*backup.BackupArn)
	return &dynamodb.Backup{
		Metadata: metadata,
	}, nil
}

func (a *adapter) getcluster() (clusters []dynamodb.DAXCluster, err error) {

	a.Tracker().SetServiceLabel("Discovering DynamoDB clusters...")

	var apiclusters []daxtype.Cluster
	var input daxApi.DescribeClustersInput
	for {
		output, err := a.client2.DescribeClusters(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiclusters = append(apiclusters, output.Clusters...)
		a.Tracker().SetTotalResources(len(apiclusters))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting DynamoDB clusters..")
	return concurrency.Adapt(apiclusters, a.RootAdapter, a.adaptcluster), nil

}

func (a *adapter) adaptcluster(cluster daxtype.Cluster) (*dynamodb.DAXCluster, error) {

	metadata := a.CreateMetadataFromARN(*cluster.ClusterArn)

	encryption := dynamodb.ServerSideEncryption{
		Metadata: metadata,
		Enabled:  defsecTypes.BoolDefault(false, metadata),
		KMSKeyID: defsecTypes.StringDefault("", metadata),
	}
	if cluster.SSEDescription != nil {

		if cluster.SSEDescription.Status == daxtype.SSEStatusEnabled {
			encryption.Enabled = defsecTypes.BoolDefault(true, metadata)
		}
	}

	return &dynamodb.DAXCluster{
		Metadata:             metadata,
		ServerSideEncryption: encryption,
		PointInTimeRecovery:  defsecTypes.BoolUnresolvable(metadata),
	}, nil
}

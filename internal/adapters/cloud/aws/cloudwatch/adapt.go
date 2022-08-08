package cloudwatch

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/state"
	cwApi "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	api "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type adapter struct {
	*aws.RootAdapter
	logsClient   *api.Client
	alarmsClient *cwApi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "cloudwatch"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.logsClient = api.NewFromConfig(root.SessionConfig())
	a.alarmsClient = cwApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CloudWatch.LogGroups, err = a.getLogGroups()
	if err != nil {
		return err
	}
	state.AWS.CloudWatch.Alarms, err = a.getAlarms()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getAlarms() ([]cloudwatch.Alarm, error) {

	a.Tracker().SetServiceLabel("Discovering alarms...")
	var apiAlarms []cwTypes.MetricAlarm

	var input cwApi.DescribeAlarmsInput
	for {
		output, err := a.alarmsClient.DescribeAlarms(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiAlarms = append(apiAlarms, output.MetricAlarms...)
		a.Tracker().SetTotalResources(len(apiAlarms))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting log groups...")

	var alarms []cloudwatch.Alarm
	for _, apiAlarm := range apiAlarms {
		alarm, err := a.adaptAlarm(apiAlarm)
		if err != nil {
			return nil, err
		}
		alarms = append(alarms, *alarm)
		a.Tracker().IncrementResource()
	}

	return alarms, nil
}

func (a *adapter) getLogGroups() ([]cloudwatch.LogGroup, error) {

	a.Tracker().SetServiceLabel("Discovering log groups...")

	var apiLogGroups []types.LogGroup
	var input api.DescribeLogGroupsInput
	for {
		output, err := a.logsClient.DescribeLogGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiLogGroups = append(apiLogGroups, output.LogGroups...)
		a.Tracker().SetTotalResources(len(apiLogGroups))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting log groups...")

	var logGroups []cloudwatch.LogGroup
	for _, apiDistribution := range apiLogGroups {
		logGroup, err := a.adaptLogGroup(apiDistribution)
		if err != nil {
			return nil, err
		}
		logGroups = append(logGroups, *logGroup)
		a.Tracker().IncrementResource()
	}

	return logGroups, nil
}

func (a *adapter) adaptLogGroup(group types.LogGroup) (*cloudwatch.LogGroup, error) {

	metadata := a.CreateMetadataFromARN(*group.Arn)

	var kmsKeyId string
	var retentionInDays int

	if group.KmsKeyId != nil {
		kmsKeyId = *group.KmsKeyId
	}

	if group.RetentionInDays != nil {
		retentionInDays = int(*group.RetentionInDays)
	}

	var metricFilters []cloudwatch.MetricFilter
	var err error
	if *group.MetricFilterCount > 0 {
		metricFilters, err = a.getMetricFilters(group.LogGroupName, metadata)
		if err != nil {
			return nil, err
		}

	}

	return &cloudwatch.LogGroup{
		Metadata:        metadata,
		Arn:             defsecTypes.String(*group.Arn, metadata),
		Name:            defsecTypes.String(*group.LogGroupName, metadata),
		KMSKeyID:        defsecTypes.String(kmsKeyId, metadata),
		RetentionInDays: defsecTypes.Int(retentionInDays, metadata),
		MetricFilters:   metricFilters,
	}, nil
}

func (a *adapter) adaptAlarm(alarm cwTypes.MetricAlarm) (*cloudwatch.Alarm, error) {

	metadata := a.CreateMetadataFromARN(*alarm.AlarmArn)

	var dimensions []cloudwatch.AlarmDimension
	for _, dimension := range alarm.Dimensions {
		dimensions = append(dimensions, cloudwatch.AlarmDimension{
			Metadata: defsecTypes.Metadata{},
			Name:     defsecTypes.String(*dimension.Name, metadata),
			Value:    defsecTypes.String(*dimension.Value, metadata),
		})
	}

	var metrics []cloudwatch.MetricDataQuery
	for _, metric := range alarm.Metrics {

		metrics = append(metrics, cloudwatch.MetricDataQuery{
			Metadata:   metadata,
			ID:         defsecTypes.String(*metric.Id, metadata),
			Expression: defsecTypes.String(*metric.Expression, metadata),
		})
	}

	return &cloudwatch.Alarm{
		Metadata:   metadata,
		AlarmName:  defsecTypes.String(*alarm.AlarmName, metadata),
		MetricName: defsecTypes.String(*alarm.MetricName, metadata),
		Dimensions: dimensions,
		Metrics:    metrics,
	}, nil
}

func (a *adapter) getMetricFilters(name *string, metadata defsecTypes.Metadata) ([]cloudwatch.MetricFilter, error) {

	var apiMetricFilters []types.MetricFilter
	input := api.DescribeMetricFiltersInput{
		LogGroupName: name,
	}
	for {
		output, err := a.logsClient.DescribeMetricFilters(a.Context(), &input)
		if err != nil {
			return nil, err
		}

		apiMetricFilters = append(apiMetricFilters, output.MetricFilters...)
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	var metricFilters []cloudwatch.MetricFilter
	for _, mf := range apiMetricFilters {
		metricFilters = append(metricFilters, cloudwatch.MetricFilter{
			Metadata:      metadata,
			FilterName:    defsecTypes.String(*mf.FilterName, metadata),
			FilterPattern: defsecTypes.String(*mf.FilterPattern, metadata),
		})

	}

	return metricFilters, nil
}

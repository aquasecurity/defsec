package cloudwatch

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type CloudWatch struct {
	LogGroups []LogGroup
	Alarms    []Alarm
}

func (w CloudWatch) GetLogGroupByArn(arn string) (logGroup *LogGroup) {
	for _, logGroup := range w.LogGroups {
		if logGroup.Arn.EqualTo(arn) {
			return &logGroup
		}
	}
	return nil
}

func (w CloudWatch) GetAlarmByMetricName(metricName string) (alarm *Alarm) {
	for _, alarm := range w.Alarms {
		if alarm.MetricName != nil && alarm.MetricName.EqualTo(metricName) {
			return &alarm
		}
	}
	return nil
}

type Alarm struct {
	defsecTypes.Metadata
	AlarmName  defsecTypes.StringValue
	MetricName defsecTypes.StringValue
	Dimensions []AlarmDimension
	Metrics    []MetricDataQuery
}

type AlarmDimension struct {
	defsecTypes.Metadata
	Name  defsecTypes.StringValue
	Value defsecTypes.StringValue
}

type MetricFilter struct {
	defsecTypes.Metadata
	FilterName    defsecTypes.StringValue
	FilterPattern defsecTypes.StringValue
}

type MetricDataQuery struct {
	defsecTypes.Metadata
	Expression defsecTypes.StringValue
	ID         defsecTypes.StringValue
}

type LogGroup struct {
	defsecTypes.Metadata
	Arn             defsecTypes.StringValue
	Name            defsecTypes.StringValue
	KMSKeyID        defsecTypes.StringValue
	RetentionInDays defsecTypes.IntValue
	MetricFilters   []MetricFilter
}

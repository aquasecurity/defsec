package cloudwatch

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
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
	types2.Metadata
	AlarmName  types2.StringValue
	MetricName types2.StringValue
	Dimensions []AlarmDimension
	Metrics    []MetricDataQuery
}

type AlarmDimension struct {
	types2.Metadata
	Name  types2.StringValue
	Value types2.StringValue
}

type MetricFilter struct {
	types2.Metadata
	FilterName    types2.StringValue
	FilterPattern types2.StringValue
}

type MetricDataQuery struct {
	types2.Metadata
	Expression types2.StringValue
	ID         types2.StringValue
}

type LogGroup struct {
	types2.Metadata
	Arn             types2.StringValue
	Name            types2.StringValue
	KMSKeyID        types2.StringValue
	RetentionInDays types2.IntValue
	MetricFilters   []MetricFilter
}

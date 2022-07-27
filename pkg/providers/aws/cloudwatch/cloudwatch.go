package cloudwatch

import (
	"github.com/aquasecurity/defsec/internal/types"
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
		if alarm.MetricName.EqualTo(metricName) {
			return &alarm
		}
	}
	return nil
}

type Alarm struct {
	types.Metadata
	AlarmName  types.StringValue
	MetricName types.StringValue
	Dimensions []AlarmDimension
	Metrics    []MetricDataQuery
}

type AlarmDimension struct {
	types.Metadata
	Name  types.StringValue
	Value types.StringValue
}

type MetricFilter struct {
	types.Metadata
	FilterName    types.StringValue
	FilterPattern types.StringValue
}

type MetricDataQuery struct {
	types.Metadata
	Expression types.StringValue
	ID         types.StringValue
}

type LogGroup struct {
	types.Metadata
	Arn             types.StringValue
	Name            types.StringValue
	KMSKeyID        types.StringValue
	RetentionInDays types.IntValue
	MetricFilters   []MetricFilter
}

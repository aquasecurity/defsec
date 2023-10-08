package cloudwatch

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getAlarms(ctx parser.FileContext) (alarms []cloudwatch.Alarm) {
	alarmres := ctx.GetResourcesByType("AWS::CloudWatch::Alarm")

	for _, r := range alarmres {

		var alarmaction []types.StringValue
		for _, am := range r.GetProperty("").AsList() {
			alarmaction = append(alarmaction, am.AsStringValue())
		}

		var dim []cloudwatch.AlarmDimension
		for _, d := range r.GetProperty("Dimension").AsList() {
			dim = append(dim, cloudwatch.AlarmDimension{
				Metadata: d.Metadata(),
				Name:     d.GetStringProperty("Name"),
				Value:    d.GetStringProperty("Value"),
			})
		}

		var dataQuery []cloudwatch.MetricDataQuery
		for _, dq := range r.GetProperty("MetricDataQuery").AsList() {
			dataQuery = append(dataQuery, cloudwatch.MetricDataQuery{
				Metadata:   dq.Metadata(),
				Expression: dq.GetStringProperty("Expression"),
				ID:         dq.GetStringProperty("Id"),
			})
		}

		alarm := cloudwatch.Alarm{
			Metadata:    r.Metadata(),
			AlarmName:   r.GetStringProperty("AlarmName"),
			MetricName:  r.GetStringProperty("MetricName"),
			AlarmAction: alarmaction,
			Dimensions:  dim,
			Metrics:     dataQuery,
		}
		alarms = append(alarms, alarm)
	}
	return alarms
}

func getLogGroups(ctx parser.FileContext) (logGroups []cloudwatch.LogGroup) {

	logGroupResources := ctx.GetResourcesByType("AWS::Logs::LogGroup")

	for _, r := range logGroupResources {
		group := cloudwatch.LogGroup{
			Metadata:        r.Metadata(),
			Arn:             types.StringDefault("", r.Metadata()),
			Name:            r.GetStringProperty("LogGroupName"),
			KMSKeyID:        r.GetStringProperty("KmsKeyId"),
			RetentionInDays: r.GetIntProperty("RetentionInDays", 0),
			MetricFilters:   getMatricfilters(ctx),
		}
		logGroups = append(logGroups, group)
	}

	return logGroups
}

func getMatricfilters(ctx parser.FileContext) (matricfilters []cloudwatch.MetricFilter) {

	matricfilterResources := ctx.GetResourcesByType("AWS::Logs::MetricFilter")

	for _, r := range matricfilterResources {

		var matrictrans []cloudwatch.MetricTransformation
		for _, mt := range r.GetProperty("MetricTransformations").AsList() {
			matrictrans = append(matrictrans, cloudwatch.MetricTransformation{
				Metadata:   mt.Metadata(),
				MetricName: mt.GetStringProperty("MetricName"),
			})
		}
		filter := cloudwatch.MetricFilter{
			Metadata:              r.Metadata(),
			LogGroupName:          r.GetStringProperty("LogGroupName"),
			FilterName:            r.GetStringProperty("FilterName"),
			FilterPattern:         r.GetStringProperty("FilterPattern"),
			MetricTransformations: matrictrans,
		}
		matricfilters = append(matricfilters, filter)
	}

	return matricfilters
}

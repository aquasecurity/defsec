package cloudwatch

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) cloudwatch.CloudWatch {
	return cloudwatch.CloudWatch{
		LogGroups: adaptLogGroups(modules),
		Alarms:    adaptMetricAlarms(modules),
	}
}

func adaptLogGroups(modules terraform.Modules) []cloudwatch.LogGroup {
	var logGroups []cloudwatch.LogGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudwatch_log_group") {
			logGroups = append(logGroups, adaptLogGroup(resource, module))
		}
	}
	return logGroups
}

func adaptLogGroup(resource *terraform.Block, module *terraform.Module) cloudwatch.LogGroup {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	if keyBlock, err := module.GetReferencedBlock(KMSKeyIDAttr, resource); err == nil {
		KMSKeyIDVal = types.String(keyBlock.FullName(), keyBlock.GetMetadata())
	}

	retentionInDaysAttr := resource.GetAttribute("retention_in_days")
	retentionInDaysVal := retentionInDaysAttr.AsIntValueOrDefault(0, resource)

	return cloudwatch.LogGroup{
		Metadata:        resource.GetMetadata(),
		Arn:             types.StringDefault("", resource.GetMetadata()),
		Name:            nameVal,
		KMSKeyID:        KMSKeyIDVal,
		RetentionInDays: retentionInDaysVal,
		MetricFilters:   getmatricfilter(resource, module),
	}
}

func getmatricfilter(resource *terraform.Block, module *terraform.Module) []cloudwatch.MetricFilter {
	var filters []cloudwatch.MetricFilter

	res := module.GetReferencingResources(resource, "aws_cloudwatch_log_metric_filter", "log_group_name")
	for _, f := range res {

		var metrictrans []cloudwatch.MetricTransformation
		for _, mt := range f.GetBlocks("") {
			metrictrans = append(metrictrans, cloudwatch.MetricTransformation{
				Metadata:   mt.GetMetadata(),
				MetricName: mt.GetAttribute("name").AsStringValueOrDefault("", mt),
			})
		}
		filters = append(filters, cloudwatch.MetricFilter{
			Metadata:              f.GetMetadata(),
			LogGroupName:          f.GetAttribute("log_group_name").AsStringValueOrDefault("", f),
			FilterName:            f.GetAttribute("name").AsStringValueOrDefault("", f),
			FilterPattern:         f.GetAttribute("pattern").AsStringValueOrDefault("", f),
			MetricTransformations: metrictrans,
		})
	}
	return filters
}

func adaptMetricAlarms(modules terraform.Modules) []cloudwatch.Alarm {
	var alarms []cloudwatch.Alarm
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudwatch_metric_alarm") {
			alarms = append(alarms, adaptMetricAlarm(resource))
		}
	}
	return alarms
}

func adaptMetricAlarm(resource *terraform.Block) cloudwatch.Alarm {

	var actions []types.StringValue
	actionblock := resource.GetAttribute("alarm_actions")
	for _, action := range actionblock.AsStringValues() {
		actions = append(actions, action)
	}

	var metricquery []cloudwatch.MetricDataQuery
	for _, d := range resource.GetBlocks("metric_query") {
		metricquery = append(metricquery, cloudwatch.MetricDataQuery{
			Metadata:   d.GetMetadata(),
			ID:         d.GetAttribute("id").AsStringValueOrDefault("", d),
			Expression: d.GetAttribute("expression").AsStringValueOrDefault("", d),
		})
	}

	return cloudwatch.Alarm{
		Metadata:    resource.GetMetadata(),
		MetricName:  resource.GetAttribute("metric_name").AsStringValueOrDefault("", resource),
		AlarmName:   resource.GetAttribute("alarm_name").AsStringValueOrDefault("", resource),
		AlarmAction: actions,
		Dimensions:  nil,
		Metrics:     metricquery,
	}
}

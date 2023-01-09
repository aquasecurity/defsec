# METADATA
# title :"VPC Flow Logs Metric Alarm"
# description: "Ensure that an AWS CloudWatch alarm exists and configured for metric filter attached with VPC flow logs CloudWatch group."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudWatch
#   severity: LOW
#   short_code: vpc-flow-logs-metric-alarm 
#   recommended_action: "Create a CloudWatch group, attached metric filter to log VPC flow logs changes and create an CloudWatch alarm for the metric filter."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            vpc_flow_log_group: settings.vpc_flow_log_group || this.settings.vpc_flow_log_group.default
#        };
#
#        if (!config.vpc_flow_log_group.length) return callback(null, results, source);
#
#        async.each(regions.cloudwatchlogs, function(region, rcb){
#            var describeMetricFilters = helpers.addSource(cache, source,
#                ['cloudwatchlogs', 'describeMetricFilters', region]);
#
#            if (!describeMetricFilters) return rcb();
#            
#            if (describeMetricFilters.err || !describeMetricFilters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to describe CloudWatch logs metric filters: ${helpers.addError(describeMetricFilters)}`, region);
#                return rcb();
#            }
#
#            if (!describeMetricFilters.data.length) {
#                helpers.addResult(results, 2,
#                    'No CloudWatch logs metric filters found', region);
#                return rcb();
#            }
#
#            let cwVpcLogGroup = describeMetricFilters.data.find(metrics => metrics.logGroupName === config.vpc_flow_log_group);
#
#            if (!cwVpcLogGroup) {
#                helpers.addResult(results, 2,
#                    'Unable to locate the specified log group', region);
#                return rcb();
#            }
#
#            let metricTransformations = cwVpcLogGroup.metricTransformations && cwVpcLogGroup.metricTransformations.length?
#                cwVpcLogGroup.metricTransformations.map(transformation => transformation.metricName) : [];
#
#            var describeAlarms = helpers.addSource(cache, source,
#                ['cloudwatch', 'describeAlarms', region]);
#
#            if (!describeAlarms ||
#                describeAlarms.err || !describeAlarms.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for CloudWatch metric alarms: ' + helpers.addError(describeAlarms), region);
#                return rcb();
#            }
#
#            if (!describeAlarms.data.length) {
#                helpers.addResult(results, 2,
#                    'No CloudWatch metric alarms found', region);
#                return rcb();
#            }
#
#            let metricAlarm =  describeAlarms.data.find(alarm => metricTransformations.includes(alarm.MetricName));
#
#            if (metricAlarm && metricAlarm.AlarmActions && metricAlarm.AlarmActions.length){
#                helpers.addResult(results, 0,
#                    'CloudWatch alarm is configured for VPC flow logs and has an SNS topic attached for notifications', 
#                    region);
#            } else if (metricAlarm) {
#                helpers.addResult(results, 0,
#                    'CloudWatch alarm is configured for the VPC flow logs but has no SNS topic attached for notifications', 
#                    region);
#            } else {
#                helpers.addResult(results, 2,
#                    'CloudWatch alarm is not configured for the VPC flow logs', 
#                    region);
#            }
#                    
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
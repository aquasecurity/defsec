# METADATA
# title :"CloudWatch Monitoring Metrics"
# description: "Ensures metric filters are setup for CloudWatch logs to detect security risks from CloudTrail."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudWatchLogs
#   severity: LOW
#   short_code: monitoring-metrics 
#   recommended_action: "Enable metric filters to detect malicious activity in CloudTrail logs sent to CloudWatch."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.cloudtrail, function(region, rcb){
#            var describeTrails = helpers.addSource(cache, source,
#                ['cloudtrail', 'describeTrails', region]);
#
#            if (!describeTrails) return rcb();
#            
#            if (describeTrails.err || !describeTrails.data) {
#                helpers.addResult(results, 3,
#                    `Unable to describe CloudTrail trails: ${helpers.addError(describeTrails)}`, region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 0,
#                    'No CloudTrail trails found', region);
#                return rcb();
#            }
#
#            var trailsInRegion = [];
#
#            for (var t in describeTrails.data) {
#                if (describeTrails.data[t].HomeRegion &&
#                    describeTrails.data[t].HomeRegion === region) {
#                    trailsInRegion.push(describeTrails.data[t]);
#                }
#            }
#
#            if (!trailsInRegion.length) {
#                helpers.addResult(results, 0,
#                    'No CloudTrail trails found in current home region', region);
#                return rcb();
#            }
#
#            var describeMetricFilters = helpers.addSource(cache, source,
#                ['cloudwatchlogs', 'describeMetricFilters', region]);
#
#            if (!describeMetricFilters ||
#                describeMetricFilters.err || !describeMetricFilters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for CloudWatchLogs metric filters: ' + helpers.addError(describeMetricFilters), region);
#                return rcb();
#            }
#
#            if (!describeMetricFilters.data.length) {
#                helpers.addResult(results, 2,
#                    'There are no CloudWatch metric filters in this region', region);
#                return rcb();
#            }
#
#            // Organize filters by log group name
#            var filters = {};
#
#            for (var f in describeMetricFilters.data) {
#                var filter = describeMetricFilters.data[f];
#
#                if (filter.logGroupName && filter.filterPattern) {
#                    if (!filters[filter.logGroupName]) filters[filter.logGroupName] = [];
#                    filters[filter.logGroupName].push(filter.filterPattern.replace(/\s+/g, '').toLowerCase());
#                }
#            }
#
#            async.each(trailsInRegion, function(trail, tcb){
#                if (!trail.CloudWatchLogsLogGroupArn) return tcb();
#
#                // CloudTrail stores the CloudWatch Log Group as a full ARN
#                // while CloudWatch Logs just stores the group name.
#                // Need to filter the name out for comparison.
#                var startPos = trail.CloudWatchLogsLogGroupArn.indexOf('log-group:') + 10;
#                var endPos = trail.CloudWatchLogsLogGroupArn.lastIndexOf(':');
#                var logGroupName = trail.CloudWatchLogsLogGroupArn.substring(startPos, endPos);
#
#                if (!filters[logGroupName]) {
#                    helpers.addResult(results, 2,
#                        'There are no CloudWatch metric filters for this trail', region,
#                        trail.TrailARN);
#
#                    return tcb();
#                }
#
#                var missing = [];
#
#                // If there is a filter setup, check for all strings.
#                for (var p in filterPatterns) {
#                    var found = false;
#                    var pattern = filterPatterns[p];
#                    var patternSearch = pattern.pattern.replace(/\s+/g, '').toLowerCase();
#
#                    for (var f in filters) {
#                        var filter = filters[f];
#
#                        if (filter.indexOf(patternSearch) > - 1) {
#                            found = true;
#                            break;
#                        }
#                    }
#
#                    if (!found) {
#                        missing.push(pattern.name);
#                    }
#                }
#
#                if (missing.length) {
#                    helpers.addResult(results, 2,
#                        'Trail logs are missing filters for: ' + missing.join(', '), region,
#                        trail.TrailARN);
#                } else {
#                    helpers.addResult(results, 0,
#                        'Trail logs have filter patterns for all required metrics', region,
#                        trail.TrailARN);
#                }
#
#                tcb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }
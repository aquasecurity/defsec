# METADATA
# title :"CloudWatch Log Retention Period"
# description: "Ensures that the CloudWatch Log retention period is set above a specified length of time."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudWatchLogs
#   severity: LOW
#   short_code: log-retention-period 
#   recommended_action: "Ensure CloudWatch logs are retained for at least 90 days."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            minimum_log_retention_period: parseInt(settings.minimum_log_retention_period || this.settings.minimum_log_retention_period.default)
#        };
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        async.each(regions.cloudwatchlogs, function(region, rcb){
#            var describeLogGroups = helpers.addSource(cache, source, ['cloudwatchlogs', 'describeLogGroups', region]);
#
#            if (!describeLogGroups || describeLogGroups.err ||
#                !describeLogGroups.data) {
#                helpers.addResult(results, 3, `Unable to query CloudWatch Logs log groups: ${helpers.addError(describeLogGroups)}`, region);
#                return rcb();
#            }
#
#            if (!describeLogGroups.data.length) {
#                helpers.addResult(results, 0, 'No CloudWatch Logs log groups found', region);
#                return rcb();
#            }
#
#            for (let logGroup of describeLogGroups.data) {
#                if (logGroup.retentionInDays) {
#                    if (logGroup.retentionInDays < config.minimum_log_retention_period) {
#                        helpers.addResult(results, 2,
#                            `Log group retention period of ${logGroup.retentionInDays} is less than required retention period of ${config.minimum_log_retention_period}`, region,
#                            logGroup.arn);
#                    } else {
#                        helpers.addResult(results, 0,
#                            `Log group retention period of ${logGroup.retentionInDays} is greater than or equal to the required retention period of ${config.minimum_log_retention_period}`, region,
#                            logGroup.arn);
#                    }
#                } else {
#                    helpers.addResult(results, 0, 'Log group retention period is set to never expire', region, logGroup.arn);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
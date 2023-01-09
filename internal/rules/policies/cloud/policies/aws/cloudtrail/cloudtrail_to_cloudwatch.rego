# METADATA
# title :"CloudTrail To CloudWatch"
# description: "Ensures CloudTrail logs are being properly delivered to CloudWatch"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudTrail
#   severity: LOW
#   short_code: cloudtrail-to-cloudwatch 
#   recommended_action: "Enable CloudTrail CloudWatch integration for all regions"
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
#                    'Unable to query for CloudTrail CloudWatch integration status: ' + helpers.addError(describeTrails), region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
#            } else if (describeTrails.data[0]) {
#                for (var t in describeTrails.data) {
#                    if (describeTrails.data[t].S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET) continue;
#                    if (!describeTrails.data[t].CloudWatchLogsLogGroupArn) {
#                        helpers.addResult(results, 2, 'CloudTrail CloudWatch integration is not enabled',
#                            region, describeTrails.data[t].TrailARN);
#                    } else {
#                        helpers.addResult(results, 0, 'CloudTrail CloudWatch integration is enabled',
#                            region, describeTrails.data[t].TrailARN);
#                    }
#                }
#            } else {
#                helpers.addResult(results, 2, 'CloudTrail is enabled but is not properly configured', region);
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
# METADATA
# title :"CloudTrail Global Services Logging Duplicated"
# description: "Ensures that AWS CloudTrail trails are not duplicating global services events in log files."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudTrail
#   severity: LOW
#   short_code: global-logging-duplicated 
#   recommended_action: "Update CloudTrail trails to log global services events enabled for only one trail"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var globalTrails = [];
#        async.each(regions.cloudtrail, function(region, rcb){
#            var describeTrails = helpers.addSource(cache, source,
#                ['cloudtrail', 'describeTrails', region]);
#
#            if (!describeTrails) return rcb();
#
#            if (describeTrails.err || !describeTrails.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for CloudTrail trails: ${helpers.addError(describeTrails)}`, region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
#                return rcb();
#            }
#
#            describeTrails.data.forEach(trail => {
#                if (!trail.TrailARN || (trail.S3BucketName && trail.S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET)) return;
#
#                if (!globalTrails.includes(trail.Name) && trail.IncludeGlobalServiceEvents) {
#                    globalTrails.push(trail.Name);
#                }
#            });
#
#            rcb();
#        }, function(){
#            if (!globalTrails.length) {
#                helpers.addResult(results, 2,
#                    'CloudTrail global services event logging is not enabled');
#            } else if (globalTrails.length < 2) {
#                helpers.addResult(results, 0,
#                    'CloudTrail global services event logs are not being duplicated');
#            } else {
#                helpers.addResult(results, 2,
#                    'CloudTrail global services event logs are being duplicated');
#            }
#
#            callback(null, results, source);
#        });
#    }
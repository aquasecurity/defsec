# METADATA
# title :"CloudTrail Enabled"
# description: "Ensures CloudTrail is enabled for all regions within an account"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudTrail
#   severity: LOW
#   short_code: cloudtrail-enabled 
#   recommended_action: "Enable CloudTrail for all regions and ensure that at least one region monitors global service events"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var globalServicesMonitored = false;
#        var globalEnabled = false;
#
#        async.each(regions.cloudtrail, function(region, rcb){
#            var describeTrails = helpers.addSource(cache, source,
#                ['cloudtrail', 'describeTrails', region]);
#
#            if (!describeTrails) return rcb();
#
#            if (describeTrails.err || !describeTrails.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for CloudTrail policy: ' + helpers.addError(describeTrails), region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
#            } else {
#                // Ensure logging is enabled
#                var found;
#
#                for (var t in describeTrails.data) {
#                    var trail = describeTrails.data[t];
#
#                    if (trail.IncludeGlobalServiceEvents) {
#                        globalServicesMonitored = true;
#                    }
#
#                    var getTrailStatus = helpers.addSource(cache, source,
#                        ['cloudtrail', 'getTrailStatus', region, trail.TrailARN]);
#
#                    if (getTrailStatus && getTrailStatus.data &&
#                        getTrailStatus.data.IsLogging) {
#
#                        if (trail.IncludeGlobalServiceEvents) {
#                            globalEnabled = true;
#                            helpers.addResult(results, 0, 'CloudTrail is enabled and monitoring regional and global services', region);
#                        } else {
#                            helpers.addResult(results, 0, 'CloudTrail is enabled and monitoring regional services', region);
#                        }
#
#                        found = true;
#                    }
#                }
#
#                if (!found) {
#                    if (globalEnabled){
#                        helpers.addResult(results, 2, 'CloudTrail is configured for global monitoring in the ' + region + ' region but is not logging API calls', region);
#                    } else {
#                        helpers.addResult(results, 2, 'CloudTrail is configured for regional monitoring but is not logging API calls', region);
#                    }
#                }
#            }
#
#            rcb();
#        }, function(){
#            if (!globalServicesMonitored) {
#                helpers.addResult(results, 2, 'CloudTrail is not configured to monitor global services');
#            } else {
#                if (globalEnabled){
#                    helpers.addResult(results, 0, 'CloudTrail is configured and enabled to monitor global services');
#                } else {
#                    helpers.addResult(results, 2, 'CloudTrail is configured but is not logging API calls for global services');
#                }
#            }
#
#            callback(null, results, source);
#        });
#    }
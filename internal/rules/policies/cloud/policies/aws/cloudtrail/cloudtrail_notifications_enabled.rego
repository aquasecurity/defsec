# METADATA
# title :"CloudTrail Notifications Enabled"
# description: "Ensure that Amazon CloudTrail trails are using active Simple Notification Service (SNS) topics to deliver notifications."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudTrail
#   severity: LOW
#   short_code: cloudtrail-notifications-enabled 
#   recommended_action: "Make sure that CloudTrail trails are using active SNS topics and that SNS topics have not been deleted after trail creation."
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
#                    `Unable to query for CloudTrail trails: ${helpers.addError(describeTrails)}`, region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 0, 'No CloudTrail trails found', region);
#                return rcb();
#            }
#
#            var listTopics = helpers.addSource(cache, source,
#                ['sns', 'listTopics', region]);
#
#            if (!listTopics) return rcb();
#
#            if (listTopics.err || !listTopics.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list SNS topics: ${helpers.addError(listTopics)}`, region);
#                return rcb();
#            }
#
#            var trailFound;
#            for (let trail of describeTrails.data) {
#                if (!trail.TrailARN ||
#                    (trail.HomeRegion && trail.HomeRegion.toLowerCase() != region)) continue;
#
#                trailFound = true;
#                var resource = trail.TrailARN;
#
#                if (!trail.SnsTopicARN) {
#                    helpers.addResult(results, 2,
#                        'CloudTrail trail has no SNS topic attached', region, resource);
#                    continue;
#                }
#
#                var getTopicAttributes = helpers.addSource(cache, source,
#                    ['sns', 'getTopicAttributes', region, trail.SnsTopicARN]);
#
#                if (!getTopicAttributes) {
#                    helpers.addResult(results, 2,
#                        'CloudTrail trail SNS topic not found', region, resource);
#                    continue;
#                } 
#
#                if (getTopicAttributes.err ||
#                    !getTopicAttributes.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to query for SNS topic attributes: ${helpers.addError(getTopicAttributes)}`, 
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'CloudTrail trail is using active SNS topic',
#                        region, resource);
#                }
#            }
#
#            if (!trailFound) {
#                helpers.addResult(results, 0, 'No CloudTrail trails found', region);
#            }
#
#            rcb();
#        }, function() {
#            return callback(null, results, source);
#        });
#    }
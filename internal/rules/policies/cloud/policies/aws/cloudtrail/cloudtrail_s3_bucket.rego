# METADATA
# title :"CloudTrail S3 Bucket"
# description: "Ensure that AWS CloudTrail trail uses the designated Amazon S3 bucket."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-update-a-trail-console.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudTrail
#   severity: LOW
#   short_code: cloudtrail-s3-bucket 
#   recommended_action: "Modify ClouTrail trails to configure designated S3 bucket"
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
#            trail_s3_bucket_name: settings.trail_s3_bucket_name || this.settings.trail_s3_bucket_name.default,
#            trails_to_check: settings.trails_to_check || this.settings.trails_to_check.default
#        };
#
#        if (!config.trail_s3_bucket_name.length) return callback(null, results, source);
#
#        var checkProvidedOnly = (config.trails_to_check.length) ? true : false;
#
#        config.trails_to_check = config.trails_to_check.split(',');
#
#        async.each(regions.cloudtrail, function(region, rcb){
#
#            var describeTrails = helpers.addSource(cache, source,
#                ['cloudtrail', 'describeTrails', region]);
#
#            if (!describeTrails) return rcb();
#
#            if (describeTrails.err || !describeTrails.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for trails: ${helpers.addError(describeTrails)}`, region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
#                return rcb();
#            }
#
#            async.each(describeTrails.data, function(trail, cb){
#                if (!trail.TrailARN || (trail.S3BucketName && trail.S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET)) return cb();
#
#                var resource = trail.TrailARN;
#
#                if (checkProvidedOnly && trail.Name && !config.trails_to_check.includes(trail.Name)) {
#                    helpers.addResult(results, 0,
#                        `CloudTrail trail "${trail.Name}" is set to pass without checking S3 bucket name`,
#                        region, resource);
#                    return cb();
#                }
#
#                if (trail.S3BucketName && trail.S3BucketName === config.trail_s3_bucket_name) {
#                    helpers.addResult(results, 0,
#                        `CloudTrail trail "${trail.Name}" has correct S3 bucket configured`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `CloudTrail trail "${trail.Name}" does not have correct S3 bucket configured`,
#                        region, resource);
#                }
#
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }
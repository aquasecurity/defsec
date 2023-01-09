# METADATA
# title :"Object Lock Enabled"
# description: "Ensures that AWS CloudTrail S3 buckets use Object Lock for data protection and regulatory compliance."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock-managing.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudTrail
#   severity: LOW
#   short_code: cloudtrail-object-lock 
#   recommended_action: "Edit trail to use a bucket with object locking enabled."
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
#
#            var describeTrails = helpers.addSource(cache, source,
#                ['cloudtrail', 'describeTrails', region]);
#
#            if (!describeTrails) return rcb();
#
#            if (describeTrails.err || !describeTrails.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for trails: ' + helpers.addError(describeTrails), region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
#                return rcb();
#            }
#
#            async.each(describeTrails.data, function(trail, cb){
#                if (!trail.S3BucketName || (trail.HomeRegion && trail.HomeRegion.toLowerCase() !== region)) return cb();
#                // Skip CloudSploit-managed events bucket
#                if (trail.S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET) return cb();
#
#                var s3Region = helpers.defaultRegion(settings);
#                var resource = 'arn:aws:s3:::' + trail.S3BucketName;
#                
#                var getObjectLockConfiguration = helpers.addSource(cache, source,
#                    ['s3', 'getObjectLockConfiguration', s3Region, trail.S3BucketName]);
#
#                if (!getObjectLockConfiguration) {
#                    helpers.addResult(results, 3,
#                        'Error querying for object lock configuration for bucket: ' + trail.S3BucketName + ': ' + helpers.addError(getObjectLockConfiguration),
#                        region, resource);
#
#                    return cb();
#                }
#
#                if (getObjectLockConfiguration.err &&
#                    getObjectLockConfiguration.err.code &&
#                    getObjectLockConfiguration.err.code === 'ObjectLockConfigurationNotFoundError') {
#                    helpers.addResult(results, 2,
#                        'Object lock is not enabled for bucket: ' + trail.S3BucketName,
#                        region, resource);
#                    return cb();
#                }
#
#                if (getObjectLockConfiguration.err || !getObjectLockConfiguration.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to query for object lock configuration for bucket: ' + trail.S3BucketName,
#                        region, resource);
#                    return cb();
#                }
#                
#                if (getObjectLockConfiguration.data.ObjectLockConfiguration &&
#                    getObjectLockConfiguration.data.ObjectLockConfiguration.ObjectLockEnabled &&
#                    getObjectLockConfiguration.data.ObjectLockConfiguration.ObjectLockEnabled.toLowerCase() === 'enabled') {
#                    helpers.addResult(results, 0,
#                        'Object lock is enabled for bucket: ' + trail.S3BucketName,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Object lock is not enabled for bucket: ' + trail.S3BucketName,
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
# METADATA
# title :"CloudTrail Bucket Access Logging"
# description: "Ensures CloudTrail logging bucket has access logging enabled to detect tampering of log files"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonS3/latest/UG/ManagingBucketLogging.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:S3
#   severity: LOW
#   short_code: cloudtrail-bucket-access-logging 
#   recommended_action: "Enable access logging on the CloudTrail bucket from the S3 console"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            whitelist_ct_access_logging_buckets: settings.whitelist_ct_access_logging_buckets ||  this.settings.whitelist_ct_access_logging_buckets.default
#        };
#        var regBucket;
#        if (config.whitelist_ct_access_logging_buckets.length) regBucket= new RegExp(config.whitelist_ct_access_logging_buckets); 
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var defaultRegion = helpers.defaultRegion(settings);
#
#        var listBuckets = helpers.addSource(cache, source,
#            ['s3', 'listBuckets', defaultRegion]);
#
#        if (!listBuckets || listBuckets.err || !listBuckets.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
#            return callback(null, results, source);
#        }
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
#                    'Unable to query for CloudTrail policy: ' + helpers.addError(describeTrails), region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 0, 'No S3 buckets to check', region);
#                return rcb();
#            }
#
#            async.each(describeTrails.data, function(trail, cb){
#                if (!trail.S3BucketName || (trail.HomeRegion && trail.HomeRegion.toLowerCase() !== region)) return cb();
#                // Skip CloudSploit-managed events bucket
#                if (trail.S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET) return cb();
#
#                if (regBucket && regBucket.test(trail.S3BucketName)) {
#                    helpers.addResult(results, 0, 
#                        'Bucket is whitelisted', region, 'arn:aws:s3:::'+trail.S3BucketName);
#                    return cb();
#                }
#
#                if (!listBuckets.data.find(bucket => bucket.Name == trail.S3BucketName)) {
#                    helpers.addResult(results, 2,
#                        'Unable to locate S3 bucket, it may have been deleted',
#                        region, 'arn:aws:s3:::' + trail.S3BucketName);
#                    return cb(); 
#                }
#
#                var s3Region = helpers.defaultRegion(settings);
#
#                var getBucketLogging = helpers.addSource(cache, source,
#                    ['s3', 'getBucketLogging', s3Region, trail.S3BucketName]);
#
#                if (!getBucketLogging || getBucketLogging.err || !getBucketLogging.data) {
#                    helpers.addResult(results, 3,
#                        'Error querying for bucket policy for bucket: ' + trail.S3BucketName + ': ' + helpers.addError(getBucketLogging),
#                        region, 'arn:aws:s3:::' + trail.S3BucketName);
#
#                    return cb();
#                }
#
#                if (getBucketLogging &&
#                    getBucketLogging.data &&
#                    getBucketLogging.data.LoggingEnabled) {
#                    helpers.addResult(results, 0,
#                        'Bucket: ' + trail.S3BucketName + ' has S3 access logs enabled',
#                        region, 'arn:aws:s3:::' + trail.S3BucketName);
#                } else {
#                    helpers.addResult(results, 1,
#                        'Bucket: ' + trail.S3BucketName + ' has S3 access logs disabled',
#                        region, 'arn:aws:s3:::' + trail.S3BucketName);
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
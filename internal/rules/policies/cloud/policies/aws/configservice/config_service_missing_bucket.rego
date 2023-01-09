# METADATA
# title :"Config Service Missing Bucket"
# description: "Ensure that Amazon Config service is pointing an S3 bucket that is active in your account in order to save configuration information"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ConfigService
#   severity: LOW
#   short_code: config-service-missing-bucket 
#   recommended_action: "Ensure that Amazon Config service is referencing an active S3 bucket in order to save configuration information."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.configservice, function(region, rcb) {
#            var describeDeliveryChannels = helpers.addSource(cache, source,
#                ['configservice', 'describeDeliveryChannels', region]);
#
#            if (!describeDeliveryChannels) return rcb();
#
#            if (describeDeliveryChannels.err || !describeDeliveryChannels.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query Config delivery channels: ' + helpers.addError(describeDeliveryChannels), region);
#                return rcb();
#            }
#
#            if (!describeDeliveryChannels.data.length) {
#                helpers.addResult(results, 0, 'No Config delivery channels found', region);
#                return rcb();
#            }
#
#            let deletedBuckets = [];
#            for (let record of describeDeliveryChannels.data) {
#                if (!record.s3BucketName) continue;
#
#                var headBucket = helpers.addSource(cache, source,
#                    ['s3', 'headBucket', region, record.s3BucketName]);
#
#                if (headBucket && headBucket.err && headBucket.err.message &&
#                    headBucket.err.message.toLowerCase().includes('not found')){
#                    deletedBuckets.push(record);
#                } else if (!headBucket || headBucket.err) {
#                    helpers.addResult(results, 3,
#                        'Unable to query S3 bucket: ' + helpers.addError(headBucket), region, 'arn:aws:s3:::' + record.s3BucketName);
#                    continue;
#                }
#            }
#
#            if (deletedBuckets.length) {
#                helpers.addResult(results, 2,
#                    `Config Service is referencing these deleted buckets: ${deletedBuckets.join(', ')}`,
#                    region);
#
#            } else {
#                helpers.addResult(results, 0,
#                    'Config Service is not referencing any deleted bucket', 
#                    region);
#            } 
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }
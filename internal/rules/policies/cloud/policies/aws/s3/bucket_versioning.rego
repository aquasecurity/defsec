# METADATA
# title :"S3 Bucket Versioning"
# description: "Ensures object versioning is enabled on S3 buckets"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:S3
#   severity: LOW
#   short_code: bucket-versioning 
#   recommended_action: "Enable object versioning for buckets with                         sensitive contents at a minimum and for all buckets                         ideally."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        var listBuckets = helpers.addSource(cache, source,
#            ['s3', 'listBuckets', region]);
#
#        if (!listBuckets) return callback(null, results, source);
#
#        if (listBuckets.err || !listBuckets.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
#            return callback(null, results, source);
#        }
#
#        if (!listBuckets.data.length) {
#            helpers.addResult(results, 0, 'No S3 buckets to check');
#            return callback(null, results, source);
#        }
#
#        listBuckets.data.forEach(function(bucket){
#            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);
#
#            var getBucketVersioning = helpers.addSource(cache, source,
#                ['s3', 'getBucketVersioning', region, bucket.Name]);
#
#            if (!getBucketVersioning || getBucketVersioning.err || !getBucketVersioning.data) {
#                helpers.addResult(results, 3,
#                    'Error querying bucket versioning for : ' + bucket.Name +
#                    ': ' + helpers.addError(getBucketVersioning),
#                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#            } else if (getBucketVersioning.data.Status == 'Enabled') {
#                helpers.addResult(results, 0,
#                    'Bucket : ' + bucket.Name + ' has versioning enabled',
#                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#            } else {
#                helpers.addResult(results, 2,
#                    'Bucket : ' + bucket.Name + ' has versioning disabled',
#                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#            }
#        });
#
#        callback(null, results, source);
#    }
# METADATA
# title :"S3 Bucket Website Enabled"
# description: "Ensures S3 buckets are not configured with static website hosting"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/premiumsupport/knowledge-center/cloudfront-https-requests-s3/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:S3
#   severity: LOW
#   short_code: bucket-website-enabled 
#   recommended_action: "Disable S3 bucket static website hosting in favor or CloudFront distributions."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#        var config = {
#            s3_website_whitelist_empty_buckets: settings.s3_website_whitelist_empty_buckets || this.settings.s3_website_whitelist_empty_buckets.default,
#        };
#        var ignoreEmptyBuckets = (config.s3_website_whitelist_empty_buckets == 'true');
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
#            if (ignoreEmptyBuckets){
#                var listObjects = helpers.addSource(cache, source,
#                    ['s3', 'listObjects', region, bucket.Name]);
#
#                if (!listObjects || listObjects.err || !listObjects.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to list S3 bucket objects: ' + helpers.addError(listObjects), bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#                    return;
#                }
#
#                if (!listObjects.data.Contents || !listObjects.data.Contents.length){
#                    helpers.addResult(results, 0,
#                        'Bucket : ' + bucket.Name + ' is empty', bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#                    return;
#                }
#            }
#
#            var getBucketWebsite = helpers.addSource(cache, source,
#                ['s3', 'getBucketWebsite', region, bucket.Name]);
#
#            if (getBucketWebsite && getBucketWebsite.err &&
#                getBucketWebsite.err.code && getBucketWebsite.err.code == 'NoSuchWebsiteConfiguration') {
#                helpers.addResult(results, 0,
#                    'Bucket : ' + bucket.Name + ' does not have static website hosting enabled',
#                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#            } else if (!getBucketWebsite || getBucketWebsite.err || !getBucketWebsite.data) {
#                helpers.addResult(results, 3,
#                    'Error querying bucket website for : ' + bucket.Name +
#                    ': ' + helpers.addError(getBucketWebsite),
#                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#            } else if (Object.keys(getBucketWebsite.data).length) {
#                helpers.addResult(results, 2,
#                    'Bucket : ' + bucket.Name + ' has static website hosting enabled',
#                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#            } else {
#                helpers.addResult(results, 0,
#                    'Bucket : ' + bucket.Name + ' does not have static website hosting enabled',
#                    bucketLocation, 'arn:aws:s3:::' + bucket.Name);
#            }
#        });
#        callback(null, results, source);
#    }
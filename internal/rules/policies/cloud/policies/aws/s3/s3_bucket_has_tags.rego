# METADATA
# title :"S3 Bucket Has Tags"
# description: "Ensure that AWS S3 Bucket have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/userguide/CostAllocTagging.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:S3
#   severity: LOW
#   short_code: s3-bucket-has-tags 
#   recommended_action: "Modify S3 buckets and add tags."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
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
#            helpers.addResult(results, 0, 'No S3 buckets found');
#            return callback(null, results, source);
#        }
#
#        const arnList = [];
#        for (var bucket of listBuckets.data) {
#            const arn = `arn:aws:s3:::${bucket.Name}`;
#            arnList.push(arn);
#        }
#        helpers.checkTags(cache, 'S3 bucket', arnList, region, results);
#        callback(null, results, source);
#    }
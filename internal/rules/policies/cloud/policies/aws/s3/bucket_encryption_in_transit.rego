# METADATA
# title :"S3 Bucket Encryption In Transit"
# description: "Ensures S3 buckets have bucket policy statements that deny insecure transport"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:S3
#   severity: LOW
#   short_code: bucket-encryption-in-transit 
#   recommended_action: "Add statements to the bucket policy that deny all S3 actions when SecureTransport is false. Resources must be list of bucket ARN and bucket ARN with wildcard."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var s3_allow_unencrypted_static_websites = settings.s3_allow_unencrypted_static_websites || this.settings.s3_allow_unencrypted_static_websites.default;
#        var allowSkipEncryption = (s3_allow_unencrypted_static_websites == 'true');
#
#        var region = helpers.defaultRegion(settings);
#
#        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);
#
#        if (!listBuckets) return callback(null, results, source);
#        if (listBuckets.err || !listBuckets.data) {
#            helpers.addResult(results, 3, `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
#            return callback(null, results, source);
#        }
#
#        if (!listBuckets.data.length) {
#            helpers.addResult(results, 0, 'No S3 buckets to check');
#            return callback(null, results, source);
#        }
#
#        for (let bucket of listBuckets.data) {
#            var bucketResource = `arn:aws:s3:::${bucket.Name}`;
#            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);
#
#            if (allowSkipEncryption) {
#                var getBucketWebsite = helpers.addSource(cache, source, ['s3', 'getBucketWebsite', region, bucket.Name]);
#                if (getBucketWebsite && getBucketWebsite.err && getBucketWebsite.err.code && getBucketWebsite.err.code === 'NoSuchWebsiteConfiguration') {
#                    // do nothing
#                } else if (!getBucketWebsite || getBucketWebsite.err || !getBucketWebsite.data) {
#                    helpers.addResult(results, 3, `Error querying for bucket website: ${bucket.Name}: ${helpers.addError(getBucketWebsite)}`, 'global', bucketResource);
#                    continue;
#                } else {
#                    helpers.addResult(results, 0,
#                        'Bucket has static website hosting enabled', 'global', bucketResource);
#                    continue;
#                }
#            }
#
#            var getBucketPolicy = helpers.addSource(cache, source, ['s3', 'getBucketPolicy', region, bucket.Name]);
#            if (getBucketPolicy && getBucketPolicy.err && getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
#                helpers.addResult(results, 2, 'No bucket policy found; encryption in transit not enforced', bucketLocation, bucketResource);
#                continue;
#            }
#            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
#                helpers.addResult(results, 3, `Error querying for bucket policy on bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, bucketLocation, bucketResource);
#                continue;
#            }
#            try {
#                // Parse the policy if it hasn't be parsed and replaced by another plugin....
#                var policyJson;
#                if (typeof getBucketPolicy.data.Policy === 'string') {
#                    policyJson = JSON.parse(getBucketPolicy.data.Policy);
#                } else {
#                    policyJson = getBucketPolicy.data.Policy;
#                }
#            } catch (e) {
#                helpers.addResult(results, 3, `Bucket policy on bucket ${bucket.Name} could not be parsed.`, bucketLocation, bucketResource);
#                continue;
#            }
#            if (!policyJson || !policyJson.Statement) {
#                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, bucketLocation, bucketResource);
#                continue;
#            }
#            if (!policyJson.Statement.length) {
#                helpers.addResult(results, 2, 'Bucket policy does not contain any statements; encryption in transit not enforced', bucketLocation, bucketResource);
#                continue;
#            }
#
#            if (policyJson.Statement.find(statement => statementDeniesInsecureTransport(statement, bucketResource))) {
#                helpers.addResult(results, 0, 'Bucket policy enforces encryption in transit', bucketLocation, bucketResource);
#            } else {
#                helpers.addResult(results, 2, 'Bucket does not enforce encryption in transit', bucketLocation, bucketResource);
#            }
#        }
#        callback(null, results, source);
#    }
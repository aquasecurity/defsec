# METADATA
# title :"S3 Bucket Enforce Object Encryption"
# description: "Ensures S3 bucket policies do not allow uploads of unencrypted objects"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/blogs/security/how-to-prevent-uploads-of-unencrypted-objects-to-amazon-s3/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:S3
#   severity: LOW
#   short_code: bucket-enforce-encryption 
#   recommended_action: "Set the S3 bucket policy to deny uploads of unencrypted objects."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            s3_enforce_encryption_require_cmk: settings.s3_enforce_encryption_require_cmk || this.settings.s3_enforce_encryption_require_cmk.default,
#            s3_enforce_encryption_allow_pattern: settings.s3_enforce_encryption_allow_pattern || this.settings.s3_enforce_encryption_allow_pattern.default,
#        };
#
#        config.s3_enforce_encryption_require_cmk = (config.s3_enforce_encryption_require_cmk == 'true');
#
#        var custom = helpers.isCustom(settings, this.settings);
#
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
#        var allowRegex = (config.s3_enforce_encryption_allow_pattern &&
#            config.s3_enforce_encryption_allow_pattern.length) ? new RegExp(config.s3_enforce_encryption_allow_pattern) : false;
#
#        for (var i in listBuckets.data) {
#            var bucket = listBuckets.data[i];
#            if (!bucket.Name) continue;
#            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);
#
#            var bucketResource = 'arn:aws:s3:::' + bucket.Name;
#
#            if (allowRegex && allowRegex.test(bucket.Name)) {
#                helpers.addResult(results, 0,
#                    'Bucket: ' + bucket.Name + ' is whitelisted via custom setting.',
#                    bucketLocation, bucketResource, custom);
#                continue;
#            }
#
#            var getBucketPolicy = helpers.addSource(cache, source,
#                ['s3', 'getBucketPolicy', region, bucket.Name]);
#
#            // Check the bucket policy
#            if (getBucketPolicy && getBucketPolicy.err &&
#                getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
#                helpers.addResult(results, 2,
#                    'No bucket policy found',
#                    bucketLocation, bucketResource);
#            } else if (!getBucketPolicy || getBucketPolicy.err ||
#                       !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
#                helpers.addResult(results, 3,
#                    'Error querying for bucket policy for bucket: ' + bucket.Name +
#                    ': ' + helpers.addError(getBucketPolicy),
#                    bucketLocation, bucketResource);
#            } else {
#                try {
#                    var policyJson;
#
#                    if (typeof getBucketPolicy.data.Policy == 'object') {
#                        policyJson = getBucketPolicy.data.Policy;
#
#                    } else {
#                        try {
#                            policyJson = JSON.parse(getBucketPolicy.data.Policy);
#                        } catch (e) {
#                            helpers.addResult(results, 3,
#                                `Error querying for bucket policy for bucket: "${bucket.Name}". Policy JSON could not be parsed`,
#                                bucketLocation, bucketResource);
#                            return;
#                        }
#                    }
#
#                    if (!policyJson || !policyJson.Statement) {
#                        helpers.addResult(results, 3,
#                            'Error querying for bucket policy for bucket: ' + bucket.Name +
#                            ': Policy JSON is invalid or does not contain valid statements.',
#                            bucketLocation, bucketResource);
#                    } else if (!policyJson.Statement.length) {
#                        helpers.addResult(results, 2,
#                            'Bucket policy does not contain any statements',
#                            bucketLocation, bucketResource);
#                    } else {
#                        var encryptionType;
#                        var nullCondition = false;
#
#                        for (var s in policyJson.Statement) {
#                            var statement = policyJson.Statement[s];
#
#                            if (statement.Effect &&
#                                statement.Effect === 'Deny' &&
#                                statement.Principal &&
#                                ((typeof statement.Principal == 'string' && statement.Principal == '*') ||
#                                 (Array.isArray(statement.Principal) && statement.indexOf('*') > -1)) &&
#                                statement.Action &&
#                                ((typeof statement.Action == 'string' && statement.Action == 's3:PutObject') ||
#                                 (Array.isArray(statement.Action) && statement.indexOf('s3:PutObject') > -1)) &&
#                                statement.Resource &&
#                                ((typeof statement.Resource == 'string' && statement.Resource == (bucketResource + '/*')) ||
#                                 (Array.isArray(statement.Principal) && statement.indexOf(bucketResource + '/*') > -1)) &&
#                                statement.Condition) {
#                                if (statement.Condition.StringNotEquals &&
#                                    statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption']) {
#                                    encryptionType = statement.Condition.StringNotEquals['s3:x-amz-server-side-encryption'];
#                                } else if (statement.Condition.Null &&
#                                    statement.Condition.Null['s3:x-amz-server-side-encryption']) {
#                                    nullCondition = true;
#                                }
#                            }
#                        }
#
#                        if (nullCondition && encryptionType) {
#                            if (config.s3_enforce_encryption_require_cmk && encryptionType !== 'aws:kms') {
#                                helpers.addResult(results, 2,
#                                    'Bucket policy requires encryption on object uploads but is not enforcing AWS KMS type',
#                                    bucketLocation, bucketResource, custom);
#                            } else {
#                                helpers.addResult(results, 0,
#                                    'Bucket policy requires encryption on object uploads',
#                                    bucketLocation, bucketResource, custom);
#                            }
#                        } else {
#                            helpers.addResult(results, 2, 'Bucket is missing required encryption enforcement policies.',
#                                bucketLocation, bucketResource);
#                        }
#                    }
#                } catch (e) {
#                    helpers.addResult(results, 3,
#                        'Error querying for bucket policy for bucket: ' + bucket.Name +
#                        ': Policy JSON could not be parsed.',
#                        bucketLocation, bucketResource);
#                }
#            }
#        }
#        
#        callback(null, results, source);
#    }
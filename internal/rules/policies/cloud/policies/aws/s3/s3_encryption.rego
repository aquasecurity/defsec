# METADATA
# title :"S3 Bucket Encryption Enforcement"
# description: "All statements in all S3 bucket policies must have a condition that requires encryption at a certain level"
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
#   short_code: s3-encryption 
#   recommended_action: "Configure a bucket policy to enforce encryption."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var desiredEncryptionLevelString = settings.s3_required_encryption_level || this.settings.s3_required_encryption_level.default;
#        var s3_allow_unencrypted_static_websites = settings.s3_allow_unencrypted_static_websites || this.settings.s3_allow_unencrypted_static_websites.default;
#        if (!desiredEncryptionLevelString.match(this.settings.s3_required_encryption_level.regex)) {
#            helpers.addResult(results, 3, 'Settings misconfigured for S3 Encryption Enforcement.');
#            return callback(null, results, source);
#        }
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
#                helpers.addResult(results, 2, 'No bucket policy found; encryption not enforced', bucketLocation, bucketResource);
#                continue;
#            }
#            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
#                helpers.addResult(results, 3, `Error querying for bucket policy on bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, bucketLocation, bucketResource);
#                continue;
#            }
#
#            try {
#                // Parse the policy if it hasn't been parsed and replaced by another plugin....
#                var policyJson;
#                if (typeof getBucketPolicy.data.Policy === 'string') {
#                    policyJson = JSON.parse(getBucketPolicy.data.Policy);
#                } else {
#                    policyJson = getBucketPolicy.data.Policy;
#                }
#            } catch (e) {
#                helpers.addResult(results, 3, `Bucket policy on bucket [${bucket.Name}] could not be parsed.`, bucketLocation, bucketResource);
#                continue;
#            }
#            if (!policyJson || !policyJson.Statement) {
#                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, bucketLocation, bucketResource);
#                continue;
#            }
#            if (!policyJson.Statement.length) {
#                helpers.addResult(results, 2, 'Bucket policy does not contain any statements; encryption not enforced', bucketLocation, bucketResource);
#                continue;
#            }
#
#            var statementEncryptionLevels = policyJson.Statement.map(statement => {
#                const encryptionLevel = getEncryptionLevel(statement);
#                if (encryptionLevel.level) return encryptionLevel.level;
#                if (encryptionLevel.key) {
#                    const keyId = encryptionLevel.key.split('/')[1];
#                    const describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);
#                    if (!describeKey || describeKey.err || !describeKey.data) {
#                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)}`, region, keyId);
#                        return 0;
#                    }
#                    return getKeyEncryptionLevel(describeKey.data.KeyMetadata);
#                }
#                return 0;
#            });
#
#            // get max encryption level string
#            const currentEncryptionLevel = statementEncryptionLevels.reduce((max, level) => encryptionLevelMap[level] > encryptionLevelMap[max] ? level : max, 'none');
#
#            if (encryptionLevelMap[currentEncryptionLevel] < encryptionLevelMap[desiredEncryptionLevelString]) {
#                helpers.addResult(results, 2, `Bucket policy does not enforce encryption to ${desiredEncryptionLevelString}, policy currently enforces: ${currentEncryptionLevel}`, bucketLocation, bucketResource);
#            } else {
#                helpers.addResult(results, 0, `Bucket policy enforces encryption to ${desiredEncryptionLevelString}, policy currently enforces: ${currentEncryptionLevel}`, bucketLocation, bucketResource);
#            }
#        }
#        callback(null, results, source);
#    }
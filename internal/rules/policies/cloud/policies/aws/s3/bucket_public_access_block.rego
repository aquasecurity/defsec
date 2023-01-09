# METADATA
# title :"S3 Bucket Public Access Block"
# description: "Ensures S3 public access block is enabled on all buckets or for AWS account"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:S3
#   severity: LOW
#   short_code: bucket-public-access-block 
#   recommended_action: "Enable the S3 public access block on all S3 buckets or for AWS account."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            s3_public_access_block_allow_pattern: settings.s3_public_access_block_allow_pattern || this.settings.s3_public_access_block_allow_pattern.default,
#            check_global_block: settings.check_global_block || this.settings.check_global_block.default
#        };
#
#        config.check_global_block = (config.check_global_block == 'true');
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);
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
#        var globalMissingBlocks = null;
#
#        if (config.check_global_block) {
#            var accountPublicAccessBlock = helpers.addSource(cache, source, ['s3control', 'getPublicAccessBlock', region, accountId]);
#
#            if (!accountPublicAccessBlock ||
#                accountPublicAccessBlock.err ||
#                !accountPublicAccessBlock.data ||
#                !accountPublicAccessBlock.data.PublicAccessBlockConfiguration) {
#                helpers.addResult(results, 3,
#                    `Unable to query public access block setting for AWS account: ${helpers.addError(accountPublicAccessBlock)}`);
#                return callback(null, results, source);
#            }
#            var configAccount = accountPublicAccessBlock.data.PublicAccessBlockConfiguration;
#            globalMissingBlocks = Object.keys(configAccount).filter(k => !configAccount[k]);
#        }
#
#        var allowRegex = (config.s3_public_access_block_allow_pattern &&
#            config.s3_public_access_block_allow_pattern.length) ? new RegExp(config.s3_public_access_block_allow_pattern) : false;
#
#        for (let { Name: bucket } of listBuckets.data) {
#            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket);
#
#            if (config.check_global_block) { 
#                if (!globalMissingBlocks.length) {
#                    helpers.addResult(results, 0, 'AWS account has public access block fully enabled', bucketLocation, `arn:aws:s3:::${bucket}`);
#                    continue;
#                }
#            }
#
#            var getPublicAccessBlock = helpers.addSource(cache, source, ['s3', 'getPublicAccessBlock', region, bucket]);
#            if (!getPublicAccessBlock) continue;
#
#            if (allowRegex && allowRegex.test(bucket)) {
#                helpers.addResult(results, 0,
#                    'Bucket: ' + bucket + ' is whitelisted via custom setting.',
#                    bucketLocation, `arn:aws:s3:::${bucket}`, custom);
#            } else {
#                if (getPublicAccessBlock.err && getPublicAccessBlock.err.code === 'NoSuchPublicAccessBlockConfiguration') {
#                    helpers.addResult(results, 2, 'S3 bucket does not have Public Access Block enabled', bucketLocation, `arn:aws:s3:::${bucket}`);
#                    continue;
#                }
#                if (getPublicAccessBlock.err || !getPublicAccessBlock.data) {
#                    helpers.addResult(results, 3, `Error: ${helpers.addError(getPublicAccessBlock)}`, bucketLocation, `arn:aws:s3:::${bucket}`);
#                    continue;
#                }
#                var configLocal = getPublicAccessBlock.data.PublicAccessBlockConfiguration;
#                var missingBlocks = Object.keys(configLocal).filter(k => !configLocal[k]);
#                if (missingBlocks.length) {
#                    helpers.addResult(results, 2, `S3 bucket is missing public access blocks: ${missingBlocks.join(', ')}`, bucketLocation, `arn:aws:s3:::${bucket}`);
#                    continue;
#                }
#                helpers.addResult(results, 0, 'S3 bucket has public access block fully enabled', bucketLocation, `arn:aws:s3:::${bucket}`);
#            }
#        }
#
#        callback(null, results, source);
#    }
# METADATA
# title :"AWS Glue S3 Encryption Enabled"
# description: "Ensures that encryption at-rest is enabled when writing AWS Glue data to Amazon S3."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Glue
#   severity: LOW
#   short_code: glue-s3-encryption-enabled 
#   recommended_action: "Recreate AWS Glue Security Configuration to enable Amazon S3 encryption at-rest"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            glue_s3_encryption_level: settings.glue_s3_encryption_level || this.settings.glue_s3_encryption_level.default,
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.glue_s3_encryption_level);
#        var currentEncryptionLevel;
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.glue, function(region, rcb){
#            var getSecurityConfigurations = helpers.addSource(cache, source,
#                ['glue', 'getSecurityConfigurations', region]);
#
#            if (!getSecurityConfigurations) return rcb();
#
#            if (getSecurityConfigurations.err || !getSecurityConfigurations.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for AWS Glue security configurations: ${helpers.addError(getSecurityConfigurations)}`, region);
#                return rcb();
#            }
#
#            if (!getSecurityConfigurations.data.length) {
#                helpers.addResult(results, 0,
#                    'No AWS Glue security configurations found', region);
#                return rcb();
#            }
#
#            async.each(getSecurityConfigurations.data, function(configuration, cb) {
#                if (!configuration.Name) return cb();
#
#                var resource = `arn:${awsOrGov}:glue:${region}:${accountId}:/securityConfiguration/${configuration.Name}`;
#                var encryptionEnabled = false;
#
#                if (configuration && configuration.EncryptionConfiguration &&
#                    configuration.EncryptionConfiguration.S3Encryption &&
#                    configuration.EncryptionConfiguration.S3Encryption.length) {
#                    for (var encryptionConfig of configuration.EncryptionConfiguration.S3Encryption) {
#                        if (encryptionConfig.S3EncryptionMode && encryptionConfig.S3EncryptionMode.toUpperCase() !== 'DISABLED') {
#                            encryptionEnabled = true;
#                            if (encryptionConfig.S3EncryptionMode.toUpperCase() === 'SSE-S3') {
#                                currentEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf('sse');
#                            } else {
#                                if (encryptionConfig.KmsKeyArn) {
#                                    var keyId = encryptionConfig.KmsKeyArn.split('/')[1];
#
#                                    var describeKey = helpers.addSource(cache, source,
#                                        ['kms', 'describeKey', region, keyId]);
#
#                                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                                        helpers.addResult(results, 3, `Unable to query associated KMS Key for configuration "${configuration.Name}": ${helpers.addError(describeKey)}`,
#                                            region, resource);
#                                        return cb();
#                                    }
#
#                                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                                } else {
#                                    helpers.addResult(results, 3, 'Unable to find associated KMS key for security configuration',
#                                        region, resource);
#                                    return cb();
#                                }
#                            }
#                            break;
#                        }
#                    }
#                }
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#                if (encryptionEnabled) {
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `Glue security configuration "${configuration.Name}" has S3 encryption enabled at encryption level ${currentEncryptionLevelString} which is greater than or equal to target level ${config.glue_s3_encryption_level}`,
#                            region, resource);    
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Glue security configuration "${configuration.Name}" has S3 encryption enabled at encryption level ${currentEncryptionLevelString} which is less than target level ${config.glue_s3_encryption_level}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        `Glue security configuration "${configuration.Name}" does not have S3 encryption enabled`,
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
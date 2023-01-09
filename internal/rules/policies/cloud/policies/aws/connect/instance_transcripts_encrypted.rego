# METADATA
# title :"Connect Instance Chat Transcripts Encrypted"
# description: "Ensure that Amazon Connect instances have encryption enabled for chat transcripts being saved on S3."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Connect
#   severity: LOW
#   short_code: instance-transcripts-encrypted 
#   recommended_action: "Modify Connect instance data storage configuration and enable encryption for chat transcripts"
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
#            desiredEncryptionLevelString: settings.connect_chat_transcripts_encryption_level || this.settings.connect_chat_transcripts_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.connect, function(region, rcb){
#            var listInstances = helpers.addSource(cache, source,
#                ['connect', 'listInstances', region]);
#
#            if (!listInstances) return rcb();
#
#            if (listInstances.err || !listInstances.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query Connect instances: ${helpers.addError(listInstances)}`, region);
#                return rcb();
#            }
#
#            if (!listInstances.data.length) {
#                helpers.addResult(results, 0, 'No Connect instances found', region);
#                return rcb();
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
#                return rcb();
#            }
#
#            for (let instance of listInstances.data) {
#                if (!instance.Arn) continue;
#
#                var resource = instance.Arn;
#
#                var listInstanceChatTranscriptStorageConfigs = helpers.addSource(cache, source,
#                    ['connect', 'listInstanceChatTranscriptStorageConfigs', region, instance.Id]);
#
#                if (!listInstanceChatTranscriptStorageConfigs || listInstanceChatTranscriptStorageConfigs.err || !listInstanceChatTranscriptStorageConfigs.data ||
#                    !listInstanceChatTranscriptStorageConfigs.data.StorageConfigs) {
#                    helpers.addResult(results, 3,
#                        `Unable to describe Connect instance chat transcripts storage config: ${helpers.addError(listInstanceChatTranscriptStorageConfigs)}`,
#                        region, resource);
#                    continue;
#                }
#
#                if (!listInstanceChatTranscriptStorageConfigs.data.StorageConfigs.length) {
#                    helpers.addResult(results, 0,
#                        'Connect instance does not have any storage config for chat transcripts',
#                        region, resource);
#                    continue;
#                }
#
#                let storageConfig = listInstanceChatTranscriptStorageConfigs.data.StorageConfigs[0];
#
#                if (storageConfig.S3Config) {
#                    if (storageConfig.S3Config.EncryptionConfig &&
#                        storageConfig.S3Config.EncryptionConfig.KeyId) {
#                        let kmsKeyArn = storageConfig.S3Config.EncryptionConfig.KeyId;
#                        let keyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;
#
#                        var describeKey = helpers.addSource(cache, source,
#                            ['kms', 'describeKey', region, keyId]);  
#    
#                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                            helpers.addResult(results, 3,
#                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                                region, kmsKeyArn);
#                            continue;
#                        }
#    
#                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#
#                        var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                            helpers.addResult(results, 0,
#                                `Connect instance is using ${currentEncryptionLevelString} for chat transcripts encryption \
#                                which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                                region, resource);
#                        } else {
#                            helpers.addResult(results, 2,
#                                `Connect instance is using ${currentEncryptionLevelString} for chat transcripts encryption \
#                                which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                                region, resource);
#                        }
#                    } else {
#                        helpers.addResult(results, 2,
#                            'Connect instance does not have encryption enabled for chat transcripts',
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 3,
#                        'Unable to find Connect instance chat transcripts S3 config',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
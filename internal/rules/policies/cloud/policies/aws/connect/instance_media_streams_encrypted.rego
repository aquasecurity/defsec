# METADATA
# title :"Connect Instance Media Streams Encrypted"
# description: "Ensure that Amazon Connect instances have encryption enabled for media streams being saved on Kinesis Video Stream."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/connect/latest/adminguide/enable-live-media-streams.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Connect
#   severity: LOW
#   short_code: instance-media-streams-encrypted 
#   recommended_action: "Modify Connect instance data storage configuration and enable encryption for media streams"
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
#            desiredEncryptionLevelString: settings.connect_media_streams_encryption_level || this.settings.connect_media_streams_encryption_level.default
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
#                var listInstanceMediaStreamStorageConfigs = helpers.addSource(cache, source,
#                    ['connect', 'listInstanceMediaStreamStorageConfigs', region, instance.Id]);
#
#                if (!listInstanceMediaStreamStorageConfigs || listInstanceMediaStreamStorageConfigs.err || !listInstanceMediaStreamStorageConfigs.data ||
#                    !listInstanceMediaStreamStorageConfigs.data.StorageConfigs) {
#                    helpers.addResult(results, 3,
#                        `Unable to describe Connect instance media streams storage config: ${helpers.addError(listInstanceMediaStreamStorageConfigs)}`,
#                        region, resource);
#                    continue;
#                }
#
#                if (!listInstanceMediaStreamStorageConfigs.data.StorageConfigs.length) {
#                    helpers.addResult(results, 0,
#                        'Connect instance does not have any media streams enabled',
#                        region, resource);
#                    continue;
#                }
#
#                let storageConfig = listInstanceMediaStreamStorageConfigs.data.StorageConfigs[0];
#
#                if (storageConfig.KinesisVideoStreamConfig) {
#                    if (storageConfig.KinesisVideoStreamConfig.EncryptionConfig &&
#                        storageConfig.KinesisVideoStreamConfig.EncryptionConfig.KeyId) {
#                        let kmsKeyArn = storageConfig.KinesisVideoStreamConfig.EncryptionConfig.KeyId;
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
#                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    } else {
#                        currentEncryptionLevel= 2; //awskms
#                    }
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#                
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `Connect instance is using ${currentEncryptionLevelString} for media streams encryption\
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Connect instance is using ${currentEncryptionLevelString} for media streams encryption\
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                   
#                } else {
#                    helpers.addResult(results, 3,
#                        'Unable to find Connect instance media streams Config',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
# METADATA
# title :"Video Stream Data Encrypted"
# description: "Ensure that Amazon Kinesis Video Streams is using desired encryption level for Data at-rest."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/how-kms.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Kinesis Video Streams
#   severity: LOW
#   short_code: videostream-data-encrypted 
#   recommended_action: "Encrypt Kinesis Video Streams data with customer-manager keys (CMKs)."
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
#            desiredEncryptionLevelString: settings.video_stream_data_desired_encryption_level || this.settings.video_stream_data_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.kinesisvideo, function(region, rcb){
#            var listStreams = helpers.addSource(cache, source,
#                ['kinesisvideo', 'listStreams', region]);
#          
#            if (!listStreams) return rcb();
#
#            if (listStreams.err || !listStreams.data) {
#                helpers.addResult(results, 3, `Unable to query Kinesis Video Streams: ${helpers.addError(listStreams)}`, region);
#                return rcb();
#            }
#
#            if (!listStreams.data.length) {
#                helpers.addResult(results, 0, 'No Kinesis Video Streams found', region);
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
#            for (let streamData of listStreams.data) {
#                if (!streamData.StreamARN) continue;
#
#                let resource = streamData.StreamARN;
#
#                if (streamData.KmsKeyId) {
#                    var kmsKeyId = streamData.KmsKeyId.split('/')[1] ? streamData.KmsKeyId.split('/')[1] : streamData.KmsKeyId;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]);  
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, streamData.KmsKeyId);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                } else currentEncryptionLevel = 2; //awskms
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `Kinesis Video Streams data is using ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Kinesis Video Streams data is using ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
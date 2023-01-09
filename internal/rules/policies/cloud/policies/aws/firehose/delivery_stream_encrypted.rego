# METADATA
# title :"Firehose Delivery Streams CMK Encrypted"
# description: "Ensures Firehose delivery stream are encrypted using AWS KMS key of desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/firehose/latest/dev/encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Firehose
#   severity: LOW
#   short_code: delivery-stream-encrypted 
#   recommended_action: "Enable encryption using desired level for all Firehose Delivery Streams."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var defaultRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);
#
#        var config = {
#            desiredEncryptionLevelString: settings.delivery_stream_desired_encryption_level || this.settings.delivery_stream_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.firehose, function(region, rcb){        
#            var listDeliveryStreams = helpers.addSource(cache, source,
#                ['firehose', 'listDeliveryStreams', region]);
#                
#            if (!listDeliveryStreams) return rcb();
#
#            if (listDeliveryStreams.err || !listDeliveryStreams.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list Firehose delivery streams: ' + helpers.addError(listDeliveryStreams), region);
#                return rcb();
#            }
#
#            if (!listDeliveryStreams.data.length) {
#                helpers.addResult(results, 0, 'No Firehose delivery streams found', region);
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
#            for (let stream of listDeliveryStreams.data) {
#                var resource = `arn:${awsOrGov}:firehose:${region}:${accountId}:deliverystream/${stream}`;
#
#                var describeDeliveryStream = helpers.addSource(cache, source,
#                    ['firehose', 'describeDeliveryStream', region, stream]);
#                    
#                if (!describeDeliveryStream || describeDeliveryStream.err || !describeDeliveryStream.data ) {
#                    helpers.addResult(results, 3,
#                        'Unable to query Firehose for delivery streams: ',
#                        region, resource);
#                    continue;
#                } 
#
#                let deliveryStreamDesc = describeDeliveryStream.data.DeliveryStreamDescription;
#
#                if (!deliveryStreamDesc ||
#                    !deliveryStreamDesc.Destinations ||
#                    !deliveryStreamDesc.Destinations[0] ||
#                    !deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription) {
#                    helpers.addResult(results, 0,
#                        'The Firehose delivery stream does not have an S3 destination',
#                        region, resource);
#                    continue;
#                }
#
#                if (deliveryStreamDesc &&
#                    deliveryStreamDesc.Destinations &&
#                    deliveryStreamDesc.Destinations[0] &&
#                    deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription &&
#                    deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration &&
#                    deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig &&
#                    deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig.AWSKMSKeyARN) {
#
#                    var kmsKeyId = deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig.AWSKMSKeyARN;
#                    var keyId = kmsKeyId.split('/')[1] ? kmsKeyId.split('/')[1] : kmsKeyId;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, keyId]);  
#                        
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, kmsKeyId);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                
#
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `Firehose delivery stream is encrypted with ${currentEncryptionLevelString} \
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Firehose delivery stream is encrypted with ${currentEncryptionLevelString} \
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'Firehose delivery stream does not have encryption enabled',
#                        region, resource);
#                }
#
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
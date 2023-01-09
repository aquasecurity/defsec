# METADATA
# title :"Firehose Delivery Streams Encrypted"
# description: "Ensures Firehose Delivery Stream encryption is enabled"
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
#   short_code: firehose-encrypted 
#   recommended_action: "Enable encryption using KMS for all Firehose Delivery Streams."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.kinesis, function(region, rcb){
#            var listDeliveryStreams = helpers.addSource(cache, source,
#                ['firehose', 'listDeliveryStreams', region]);
#
#            if (!listDeliveryStreams) return rcb();
#
#            if (listDeliveryStreams.err) {
#                helpers.addResult(results, 3,
#                    'Unable to list Firehose delivery streams: ' + helpers.addError(listDeliveryStreams), region);
#                return rcb();
#            }
#
#            if (!listDeliveryStreams.data || !listDeliveryStreams.data.length) {
#                helpers.addResult(results, 0, 'No Firehose delivery streams found', region);
#                return rcb();
#            }
#
#            async.each(listDeliveryStreams.data, function(deliverystream, cb){
#
#                var describeDeliveryStream = helpers.addSource(cache, source,
#                    ['firehose', 'describeDeliveryStream', region, deliverystream]);
#                
#                if (!describeDeliveryStream ||
#                    (!describeDeliveryStream.err && !describeDeliveryStream.data)) {
#                    return cb();
#                }
#
#                if (describeDeliveryStream.err || !describeDeliveryStream.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to query Firehose for delivery streams: ' + deliverystream,
#                        region);
#                    return cb();
#                }
#                
#                var deliveryStreamDesc = describeDeliveryStream.data.DeliveryStreamDescription;
#                var deliveryStreamARN = deliveryStreamDesc.DeliveryStreamARN;
#
#
#                if (!deliveryStreamDesc ||
#                    !deliveryStreamDesc.Destinations ||
#                    !deliveryStreamDesc.Destinations[0] ||
#                    !deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription) {
#                    helpers.addResult(results, 0,
#                        'The Firehose delivery stream does not have an S3 destination',
#                        region, deliveryStreamARN);
#                    return cb();
#                }
#
#                if (deliveryStreamDesc &&
#                    deliveryStreamDesc.Destinations &&
#                    deliveryStreamDesc.Destinations[0] &&
#                    deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription &&
#                    deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration &&
#                    deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig) {
#                    if (deliveryStreamDesc.Destinations[0].ExtendedS3DestinationDescription.EncryptionConfiguration.KMSEncryptionConfig === defaultKmsKey) {
#                        //Note: Default KeyARN returns, but doesn't match the alias
#                        helpers.addResult(results, 1,
#                            'The Firehose delivery stream uses the default KMS key (' + defaultKmsKey + ') for SSE',
#                            region, deliveryStreamARN);
#                    } else {
#                        helpers.addResult(results, 0,
#                            'The Firehose delivery stream uses a KMS key for SSE',
#                            region, deliveryStreamARN);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'The Firehose delivery stream does not use a KMS key for SSE',
#                        region, deliveryStreamARN);
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
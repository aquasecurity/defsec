# METADATA
# title :"Kinesis Data Streams Encrypted"
# description: "Ensures Kinesis data streams are encrypted using AWS KMS key of desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Kinesis
#   severity: LOW
#   short_code: kinesis-data-streams-encrypted 
#   recommended_action: "Enable encryption using desired level for all Kinesis streams"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        var config = {
#            desiredEncryptionLevelString: settings.data_streams_desired_encryption_level || this.settings.data_streams_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.kinesis, function(region, rcb){
#            var listStreams = helpers.addSource(cache, source,
#                ['kinesis', 'listStreams', region]);
#
#            if (!listStreams) return rcb();
#
#            if (listStreams.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Kinesis streams: ' + helpers.addError(listStreams), region);
#                return rcb();
#            }
#
#            if (!listStreams.data || !listStreams.data.length) {
#                helpers.addResult(results, 0, 'No Kinesis streams found', region);
#                return rcb();
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list KMS keys:' + helpers.addError(listKeys), region);
#                return rcb();
#            }   
#
#            var listAliases = helpers.addSource(cache, source,
#                ['kms', 'listAliases', region]);
#
#            if (!listAliases || listAliases.err || !listAliases.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for KMS aliases: ' + helpers.addError(listAliases),
#                    region);
#                return rcb();
#            }
#            
#            var keyArn;
#            var kmsAliasArnMap = {};
#            listAliases.data.forEach(function(alias){
#                keyArn = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
#                kmsAliasArnMap[alias.AliasName] = keyArn;
#            });
#
#            for (let stream of listStreams.data) {
#                let resource = `arn:${awsOrGov}:kinesis:${region}:${accountId}:stream/${stream}`;
#                
#                var describeStream = helpers.addSource(cache, source,
#                    ['kinesis', 'describeStream', region, stream]);
#
#                if (!describeStream || describeStream.err || !describeStream.data || !describeStream.data.StreamDescription) {
#                    helpers.addResult(results, 3,
#                        'Unable to query Kinesis for stream: ' + stream + ': ' + helpers.addError(describeStream),
#                        region, resource);
#                    continue;
#                }
#
#                if (describeStream.data.StreamDescription.KeyId) {
#                    var encryptionKey = describeStream.data.StreamDescription.KeyId;
#
#                    let kmsKeyArn = (encryptionKey.startsWith('alias/')) ?
#                        (kmsAliasArnMap[encryptionKey]) ? kmsAliasArnMap[encryptionKey] :
#                            encryptionKey : encryptionKey;
#
#                    var keyId = kmsKeyArn.split('/')[1] ? kmsKeyArn.split('/')[1] : kmsKeyArn;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, keyId]);
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, kmsKeyArn);
#                        continue;
#                    }
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#
#                    let currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `Kinesis stream is encrypted with ${currentEncryptionLevelString} \
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Kinesis stream is encrypted with ${currentEncryptionLevelString} \
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'Kinesis stream does not have encryption enabled',
#                        region, resource);
#                }
#                
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
# METADATA
# title :"Tracker Data Encrypted"
# description: "Ensure that Amazon Location tracker data is encrypted using desired KMS encryption level"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/location/latest/developerguide/encryption-at-rest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Location
#   severity: LOW
#   short_code: tracker-data-encrypted 
#   recommended_action: "Encrypt Amazon Location tracker with customer-manager keys (CMKs)"
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
#            desiredEncryptionLevelString: settings.location_trackerdata_desired_encryption_level || this.settings.location_trackerdata_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.location, function(region, rcb){        
#            var listTrackers = helpers.addSource(cache, source,
#                ['location', 'listTrackers', region]);
#
#            if (!listTrackers) return rcb();
#
#            if (listTrackers.err || !listTrackers.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query Location trackers: ' + helpers.addError(listTrackers), region);
#                return rcb();
#            }
#
#            if (!listTrackers.data.length) {
#                helpers.addResult(results, 0, 'No Location trackers found', region);
#                return rcb();
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#              
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
#                return rcb();
#            }
#
#            for (let tracker of listTrackers.data) {
#                var resource = `arn:${awsOrGov}:geo:${region}:${accountId}:tracker/${tracker.TrackerName}`;
#               
#                var describeTracker = helpers.addSource(cache, source,
#                    ['location', 'describeTracker', region, tracker.TrackerName]);
#
#                if (!describeTracker || describeTracker.err || !describeTracker.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to get Location Tracker: ${helpers.addError(describeTracker)}`,
#                        region, resource);
#                    continue;
#                } 
#
#                if (describeTracker.data.KmsKeyId) {
#                    var kmsKey = describeTracker.data.KmsKeyId;
#                    var keyId = kmsKey.split('/')[1] ? kmsKey.split('/')[1] : kmsKey;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, keyId]);  
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, kmsKey);
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
#                        `Tracker data is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Tracker data is encrypted with ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
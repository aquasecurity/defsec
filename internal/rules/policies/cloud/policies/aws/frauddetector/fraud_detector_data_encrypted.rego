# METADATA
# title :"Fraud Detector Data Encrypted"
# description: "Ensure that Amazon Fraud Detector has encryption enabled for data at rest with desired KMS encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/frauddetector/latest/ug/encryption-at-rest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Fraud Detector
#   severity: LOW
#   short_code: fraud-detector-data-encrypted 
#   recommended_action: "Enable encryption for data at rest using PutKMSEncryptionKey API"
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
#            desiredEncryptionLevelString: settings.fraud_detector_data_encryption_level || this.settings.fraud_detector_data_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.connect, function(region, rcb){
#            var listDetectors = helpers.addSource(cache, source,
#                ['frauddetector', 'getDetectors', region]);
#
#            if (!listDetectors) return rcb();
#
#            if (listDetectors.err || !listDetectors.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query Fraud Detectors: ${helpers.addError(listDetectors)}`, region);
#                return rcb();
#            }
#
#            if (!listDetectors.data.length) {
#                helpers.addResult(results, 0, 'No Fraud Detectors found', region);
#                return rcb();
#            }
#
#            var fraudDetectorsEncryptionKey = helpers.addSource(cache, source,
#                ['frauddetector', 'getKMSEncryptionKey', region]);
#
#            if (fraudDetectorsEncryptionKey.err || !fraudDetectorsEncryptionKey.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query Fraud Detectors Key: ${helpers.addError(listDetectors)}`, region);
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
#            if (fraudDetectorsEncryptionKey.data && fraudDetectorsEncryptionKey.data.kmsEncryptionKeyArn
#                    && fraudDetectorsEncryptionKey.data.kmsEncryptionKeyArn.toUpperCase() !== 'DEFAULT') {
#                let encryptionKey = fraudDetectorsEncryptionKey.data.kmsEncryptionKeyArn;
#                var keyId = encryptionKey.split('/')[1] ? encryptionKey.split('/')[1] : encryptionKey;
#
#                var describeKey = helpers.addSource(cache, source,
#                    ['kms', 'describeKey', region, keyId]);
#
#                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3,
#                        `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                        region, encryptionKey);
#                    return rcb();    
#                }
#
#                currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#
#            } else {
#                currentEncryptionLevel = 2; //awskms
#            }
#
#            var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#            if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                helpers.addResult(results, 0,
#                    `Fraud Detectors Data is encrypted with ${currentEncryptionLevelString} \
#                    which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                    region);
#            } else {
#                helpers.addResult(results, 2,
#                    `Fraud Detectors Data is encrypted with ${currentEncryptionLevelString} \
#                    which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                    region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
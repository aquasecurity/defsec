# METADATA
# title :"Audit Manager Data Encrypted"
# description: "Ensure that all data in Audit Manager is encrypted with desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/audit-manager/latest/userguide/data-protection.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Audit Manager
#   severity: LOW
#   short_code: auditmanager-data-encrypted 
#   recommended_action: "Modify Audit Manager data encryption settings and choose desired encryption key for data encryption"
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
#            desiredEncryptionLevelString: settings.auditmanager_data_encryption_level || this.settings.auditmanager_data_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        for (let region of regions.auditmanager) {
#            var getSettings = helpers.addSource(cache, source,
#                ['auditmanager', 'getSettings', region]);
#
#            if (!getSettings) continue;
#
#            if (getSettings.err && getSettings.err.message && getSettings.err.message.includes('Please complete AWS Audit Manager setup')) {
#                helpers.addResult(results, 0,
#                    'Audit Manager is not setp up for this region', region);
#                continue;
#            } else if (getSettings.err || !getSettings.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query Audit Manager settings: ${helpers.addError(getSettings)}`, region);
#                continue;
#            }
#
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
#                continue;
#            }
#
#            if (getSettings.data.kmsKey && getSettings.data.kmsKey.length) {
#                if (getSettings.data.kmsKey.toUpperCase() == 'DEFAULT') {
#                    currentEncryptionLevel = 2; //awskms
#                } else {
#                    var kmsKeyId = getSettings.data.kmsKey.split('/')[1] ? getSettings.data.kmsKey.split('/')[1] : getSettings.data.kmsKey;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]);
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, getSettings.data.kmsKey);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                }
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `Audit Manager data is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region);
#                } else {
#                    helpers.addResult(results, 2,
#                        `Audit Manager data is encrypted with ${currentEncryptionLevelString} \
#                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region);
#                }
#            } else {
#                helpers.addResult(results, 3,
#                    'Unable to retrieve encryption settings for Audit Manager data', region);
#            }
#        }
#
#        callback(null, results, source);
#    }
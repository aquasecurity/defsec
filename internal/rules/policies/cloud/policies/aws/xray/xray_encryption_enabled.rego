# METADATA
# title :"XRay Encryption Enabled"
# description: "Ensures CMK-based encryption is enabled for XRay traces."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/xray/latest/devguide/xray-console-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:XRay
#   severity: LOW
#   short_code: xray-encryption-enabled 
#   recommended_action: "Update XRay encryption configuration to use a CMK."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            xray_encryption_level: settings.xray_encryption_level || this.settings.xray_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.xray_encryption_level);
#        var currentEncryptionLevel;
#        var currentEncryptionLevelString;
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.xray, function(region, rcb){
#            var getEncryptionConfig = helpers.addSource(cache, source,
#                ['xray', 'getEncryptionConfig', region]);
#
#            if (!getEncryptionConfig) return rcb();
#
#            if (getEncryptionConfig.err || !getEncryptionConfig.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for XRay encryption configuration: ' + helpers.addError(getEncryptionConfig), region);
#                return rcb();
#            }
#
#            if (getEncryptionConfig.data &&
#                getEncryptionConfig.data.Type &&
#                getEncryptionConfig.data.Type == 'KMS' &&
#                getEncryptionConfig.data.KeyId) {
#                var kmsKeyId = getEncryptionConfig.data.KeyId.split('/')[1];
#
#                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);
#
#                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3,
#                        `Unable to query KMS key: ${helpers.addError(describeKey)}`, region);
#                    return rcb();
#                }
#
#                currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0, `XRay is configured to use encryption at level ${currentEncryptionLevelString} which is greater than or equal to desired level ${config.xray_encryption_level}`, region);
#                } else {
#                    helpers.addResult(results, 2, `XRay is configured to use encryption at level ${currentEncryptionLevelString} which is less than desired level ${config.xray_encryption_level}`, region);
#                }
#            } else {
#                currentEncryptionLevel = 1; //sse
#                currentEncryptionLevelString = 'sse';
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0, `XRay is configured to use encryption at level ${currentEncryptionLevelString} which is greater than or equal to desired level ${config.xray_encryption_level}`, region);
#                } else {
#                    helpers.addResult(results, 2, `XRay is configured to use encryption at level ${currentEncryptionLevelString} which is less than desired level ${config.xray_encryption_level}`, region);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
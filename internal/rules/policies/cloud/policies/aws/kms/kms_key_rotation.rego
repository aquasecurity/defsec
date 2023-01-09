# METADATA
# title :"KMS Key Rotation"
# description: "Ensures KMS keys are set to rotate on a regular schedule"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:KMS
#   severity: LOW
#   short_code: kms-key-rotation 
#   recommended_action: "Enable yearly rotation for the KMS key"
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
#            kms_key_policy_whitelisted_policy_ids: settings.kms_key_policy_whitelisted_policy_ids || this.settings.kms_key_policy_whitelisted_policy_ids.default
#        };
#
#        if (config.kms_key_policy_whitelisted_policy_ids &&
#            config.kms_key_policy_whitelisted_policy_ids.length) {
#            config.kms_key_policy_whitelisted_policy_ids = config.kms_key_policy_whitelisted_policy_ids.split(',');
#        } else {
#            config.kms_key_policy_whitelisted_policy_ids = [];
#        }
#
#        async.each(regions.kms, function(region, rcb){
#            
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys) return rcb();
#
#            if (listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
#                return rcb();
#            }
#
#            if (!listKeys.data.length) {
#                helpers.addResult(results, 0, 'No KMS keys found', region);
#                return rcb();                
#            }
#
#            var noCmks = true;
#            listKeys.data.forEach(kmsKey => {
#                if (!kmsKey.KeyId) return;
#
#                var getKeyPolicy = helpers.addSource(cache, source,
#                    ['kms', 'getKeyPolicy', region, kmsKey.KeyId]);
#
#                if (!getKeyPolicy || getKeyPolicy.err || !getKeyPolicy.data){
#                    helpers.addResult(results, 3,
#                        'Unable to get key policy: ' + helpers.addError(getKeyPolicy),
#                        region, kmsKey.KeyArn);
#                    return;
#                }
#
#                // Auq-CSPM keys for Remediations should be skipped. 
#                // The only way to distinguish these keys is the Policy Id.
#                if (getKeyPolicy.data.Id &&
#                    config.kms_key_policy_whitelisted_policy_ids.length &&
#                    config.kms_key_policy_whitelisted_policy_ids.indexOf(getKeyPolicy.data.Id)>-1) {
#                    helpers.addResult(results, 0, 'The key ' + kmsKey.KeyArn + ' is whitelisted.', region, kmsKey.KeyArn);
#                    return;
#                }
#
#                var describeKey = helpers.addSource(cache, source,
#                    ['kms', 'describeKey', region, kmsKey.KeyId]);
#                
#                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3,
#                        'Unable to describe key: ' + helpers.addError(describeKey),
#                        region, kmsKey.KeyArn);
#                    return;
#                }
#
#                var describeKeyData = describeKey.data;
#
#                // AWS-generated keys for CodeCommit, ACM, etc. should be skipped.
#                // Also skip keys that are being deleted 
#                const currentEncryptionLevel = helpers.getEncryptionLevel(describeKeyData.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                if (currentEncryptionLevel <= 2 ||
#                    (describeKeyData.KeyMetadata.KeyState &&
#                    describeKeyData.KeyMetadata.KeyState.toUpperCase() === 'PENDINGDELETION'))  return;
#
#                // Skip keys that are imported into KMS
#                if (describeKeyData.KeyMetadata &&
#                    describeKeyData.KeyMetadata.Origin &&
#                    describeKeyData.KeyMetadata.Origin !== 'AWS_KMS') {
#                    return;
#                }
#
#                var getKeyRotationStatus = helpers.addSource(cache, source,
#                    ['kms', 'getKeyRotationStatus', region, kmsKey.KeyId]);
#                
#                if (!getKeyRotationStatus || getKeyRotationStatus.err || !getKeyRotationStatus.data){
#                    helpers.addResult(results, 3,
#                        'Unable to get key rotation status: ' + helpers.addError(getKeyRotationStatus),
#                        region, kmsKey.KeyArn);
#                    return;
#                }
#
#                noCmks = false;
#                var enabled = getKeyRotationStatus.data.KeyRotationEnabled;
#                var status = enabled ? 0 : 2;
#
#                helpers.addResult(results, status, `Key rotation is ${enabled ? '' : 'not'} enabled`, region, kmsKey.KeyArn);
#            });
#
#            if (noCmks) {
#                helpers.addResult(results, 0, 'No customer-managed KMS keys found', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
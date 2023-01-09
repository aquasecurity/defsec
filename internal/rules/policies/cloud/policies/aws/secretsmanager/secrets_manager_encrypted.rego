# METADATA
# title :"Secrets Manager Encrypted Secrets"
# description: "Ensures Secrets Manager Secrets are encrypted"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/secretsmanager/latest/userguide/data-protection.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Secrets Manager
#   severity: LOW
#   short_code: secrets-manager-encrypted 
#   recommended_action: "Encrypt Secrets Manager Secrets"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var desiredEncryptionLevelString = settings.secretsmanager_minimum_encryption_level || this.settings.secretsmanager_minimum_encryption_level.default;
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(desiredEncryptionLevelString);
#
#        async.each(regions.secretsmanager, (region, rcb) => {
#            var listSecrets = helpers.addSource(cache, source, ['secretsmanager', 'listSecrets', region]);
#
#            if (!listSecrets) return rcb();
#
#            if (!listSecrets.data || listSecrets.err) {
#                helpers.addResult(results, 3, `Unable to query for secrets: ${helpers.addError(listSecrets)}`, region);
#                return rcb();
#            }
#
#            if (!listSecrets.data.length) {
#                helpers.addResult(results, 0, 'No secrets found', region);
#                return rcb();
#            }
#
#            for (let secret of listSecrets.data) {
#                let encryptionLevel;
#                let encryptionLevelString;
#
#                if (!secret.KmsKeyId) encryptionLevel = 2; //awskms
#                else {
#                    const keyId = secret.KmsKeyId.startsWith('arn:aws:kms')
#                        ? secret.KmsKeyId.split('/')[1]
#                        : secret.KmsKeyId;
#
#                    const describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)}`, region, keyId);
#                        continue;
#                    }
#
#                    encryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                }
#
#                encryptionLevelString = helpers.ENCRYPTION_LEVELS[encryptionLevel];
#
#                if (encryptionLevel < desiredEncryptionLevel) {
#                    helpers.addResult(results, 2, `Secret configured to use ${encryptionLevelString} instead of ${desiredEncryptionLevelString}`, region, secret.ARN);
#                } else {
#                    helpers.addResult(results, 0, `Secret configured to use desired encryption ${encryptionLevelString}`, region, secret.ARN);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
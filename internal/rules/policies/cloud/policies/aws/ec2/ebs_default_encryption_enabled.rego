# METADATA
# title :"EBS Encryption Enabled By Default"
# description: "Ensure the setting for encryption by default is enabled"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ebs-default-encryption-enabled 
#   recommended_action: "Enable EBS Encryption by Default"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var ebs_encryption_level = settings.ebs_encryption_level || this.settings.ebs_encryption_level.default;
#        var targetEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(ebs_encryption_level);
#
#        async.each(regions.ec2, function(region, rcb){
#            var getEbsEncryptionByDefault = helpers.addSource(cache, source,
#                ['ec2', 'getEbsEncryptionByDefault', region]);
#
#            if (!getEbsEncryptionByDefault) return rcb();
#
#            if (getEbsEncryptionByDefault.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for ebs encryption by default: ' + helpers.addError(getEbsEncryptionByDefault), region);
#                return rcb();
#            }
#
#            if (!getEbsEncryptionByDefault.data) {
#                helpers.addResult(results, 2,
#                    'EBS default encryption is disabled', region);
#                return rcb();
#            }
#
#            var getEbsDefaultKmsKeyId = helpers.addSource(cache, source,
#                ['ec2', 'getEbsDefaultKmsKeyId', region]);
#
#            if (!getEbsDefaultKmsKeyId || getEbsDefaultKmsKeyId.err || !getEbsDefaultKmsKeyId.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for ebs default kms key id: ' + helpers.addError(getEbsDefaultKmsKeyId), region);
#                return rcb();
#            }
#
#            var kmsKeyId = '';
#            var isPredefinedAlias = false;
#            if (getEbsDefaultKmsKeyId.data.split('/')[0] === 'alias') {
#                var listAliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);
#
#                if (!listAliases || listAliases.err || !listAliases.data) {
#                    helpers.addResult(results, 3, 'Unable to query for list aliases: ' + helpers.addError(listAliases), region);
#                    return rcb();
#                }
#
#                listAliases.data.forEach(function(alias){
#                    if (alias.AliasName === getEbsDefaultKmsKeyId.data) {
#                        if (alias.TargetKeyId) {
#                            kmsKeyId = alias.TargetKeyId;
#                        } else {
#                            isPredefinedAlias = true;
#                        }
#                    }
#                });
#            } else {
#                kmsKeyId = getEbsDefaultKmsKeyId.data.split('/')[1];
#            }
#
#            var encryptionLevel;
#            if (!isPredefinedAlias) {
#                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);
#                
#                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3,
#                        'Unable to query kms key: ' + helpers.addError(describeKey), region);
#                    return rcb();
#                }
#
#                encryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#            } else {
#                encryptionLevel = 2; //awskms
#            }
#
#            if (encryptionLevel < targetEncryptionLevel) {
#                helpers.addResult(results, 2,
#                    `EBS default encryption is enabled but current encryption level ${helpers.ENCRYPTION_LEVELS[encryptionLevel]} is less than the target level ${helpers.ENCRYPTION_LEVELS[targetEncryptionLevel]}`, region);
#            } else {
#                helpers.addResult(results, 0,
#                    `EBS default encryption is enabled and current encryption level ${helpers.ENCRYPTION_LEVELS[encryptionLevel]} is greater than or equal to the target level ${helpers.ENCRYPTION_LEVELS[targetEncryptionLevel]}`, region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
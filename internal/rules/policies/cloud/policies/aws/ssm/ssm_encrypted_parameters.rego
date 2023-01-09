# METADATA
# title :"SSM Encrypted Parameters"
# description: "Ensures SSM Parameters are encrypted"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html#sysman-paramstore-securestring
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:SSM
#   severity: LOW
#   short_code: ssm-encrypted-parameters 
#   recommended_action: "Recreate unencrypted SSM Parameters with Type set to SecureString."
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
#            ssm_encryption_level: settings.ssm_encryption_level || this.settings.ssm_encryption_level.default,
#            allow_ssm_non_secure_strings: settings.allow_ssm_non_secure_strings || this.settings.allow_ssm_non_secure_strings.default
#        };
#
#        config.allow_ssm_non_secure_strings = (config.allow_ssm_non_secure_strings == 'true');
#
#        var desiredEncryptionLevelString = settings.ssm_encryption_level || this.settings.ssm_encryption_level.default;
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(desiredEncryptionLevelString);
#
#        async.each(regions.ssm, function(region, rcb){
#            var describeParameters = helpers.addSource(cache, source,
#                ['ssm', 'describeParameters', region]);
#
#            if (!describeParameters) return rcb();
#
#            if (describeParameters.err || !describeParameters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Parameters: ${helpers.addError(describeParameters)}`, region);
#                return rcb();
#            }
#
#            if (!describeParameters.data.length) {
#                helpers.addResult(results, 0, 'No Parameters present', region);
#                return rcb();
#            }
#
#            var aliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);
#
#            if (!aliases || aliases.err || !aliases.data) {
#                helpers.addResult(results, 3, `Unable to query KMS Aliases: ${helpers.addError(aliases)}`, region);
#                return rcb();
#            }
#
#            async.each(describeParameters.data, function(param, pcb){
#                var parameterName = param.Name.charAt(0) === '/' ? param.Name.substr(1) : param.Name;
#                var arn = `arn:${awsOrGov}:ssm:${region}:${accountId}:parameter/${parameterName}`;
#
#                if (param.Type != 'SecureString' && !config.allow_ssm_non_secure_strings) {
#                    helpers.addResult(results, 2, 'Non-SecureString Parameters present', region, arn);
#                    return pcb();
#                }
#
#                if (param.Type != 'SecureString' && config.allow_ssm_non_secure_strings) {
#                    helpers.addResult(results, 0, 'Non-SecureString Parameters present but are allowed', region, arn);
#                    return pcb();
#                }
#
#                var keyId;
#                if (!param.KeyId) {
#                    helpers.addResult(results, 2, 'SSM Parameters is not encrypted', region, arn);
#                    return pcb();
#                }
#
#                if (param.KeyId.includes('alias')) {
#                    var alias = aliases.data.find(a => a.AliasName === param.KeyId);
#                    if (!alias || !alias.TargetKeyId) {
#                        helpers.addResult(results, 3, `Unable to locate alias: ${param.KeyId} for SSM Parameter`, region, arn);
#                        return pcb();
#                    }
#                    keyId = alias.TargetKeyId;
#                } else {
#                    keyId = param.KeyId.split('/')[1];
#                }
#
#                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);
#
#                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                    helpers.addResult(results, 3, `Unable to query KMS Key: ${keyId}`, region, arn);
#                    return pcb();
#                }
#
#                var currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel < desiredEncryptionLevel) {
#                    helpers.addResult(results, 2, 
#                        `SSM Parameter is encrypted to ${currentEncryptionLevelString}, which is lower than the desired ${desiredEncryptionLevelString} level`,
#                        region, arn);
#                } else {
#                    helpers.addResult(results, 0,
#                        `SSM Parameter is encrypted to a minimum desired level of ${desiredEncryptionLevelString}`,
#                        region, arn);
#                }
#
#                pcb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }
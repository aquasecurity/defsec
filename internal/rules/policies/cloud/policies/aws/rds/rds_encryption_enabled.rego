# METADATA
# title :"RDS Encryption Enabled"
# description: "Ensures at-rest encryption is setup for RDS instances"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:RDS
#   severity: LOW
#   short_code: rds-encryption-enabled 
#   recommended_action: "RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with encryption enabled."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            rds_encryption_kms_alias: settings.rds_encryption_kms_alias || this.settings.rds_encryption_kms_alias.default,
#            desiredEncryptionLevelString: settings.rds_encryption_level || this.settings.rds_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        var custom = helpers.isCustom(settings, this.settings);
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.rds, function(region, rcb){
#            var describeDBInstances = helpers.addSource(cache, source,
#                ['rds', 'describeDBInstances', region]);
#
#            if (!describeDBInstances) return rcb();
#
#            if (describeDBInstances.err || !describeDBInstances.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
#                return rcb();
#            }
#
#            if (!describeDBInstances.data.length) {
#                helpers.addResult(results, 0, 'No RDS instances found', region);
#                return rcb();
#            }
#
#            var listAliases = helpers.addSource(cache, source,
#                ['kms', 'listAliases', region]);
#
#            var aliasId;
#            if (config.rds_encryption_kms_alias) {
#                if (!listAliases || listAliases.err ||
#                    !listAliases.data) {
#                    helpers.addResult(results, 3, `RDS KMS alias setting is configured but KMS aliases could not be obtained: ${helpers.addError(listAliases)}`, region, null, custom);
#                    return rcb();
#                }
#
#                if (!listAliases.data.length) {
#                    helpers.addResult(results, 2, 'RDS KMS alias setting is configured but there are no KMS aliases.', region, null, custom);
#                    return rcb();
#                }
#
#                listAliases.data.forEach(function(alias){
#                    if (alias.AliasName == config.rds_encryption_kms_alias) {
#                        aliasId = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
#                    }
#                });
#
#                if (!aliasId) {
#                    helpers.addResult(results, 2, `RDS KMS alias setting is configured but the specified alias (${config.rds_encryption_kms_alias}) was not found.`, region, null, custom);
#                    return rcb();
#                }
#            }
#
#            for (var i in describeDBInstances.data) {
#                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
#                var db = describeDBInstances.data[i];
#                var dbResource = db.DBInstanceArn;
#                var kmsKey = db.KmsKeyId;
#
#                if (db.StorageEncrypted) {
#                    var keyId = kmsKey.split('/')[1];
#                    var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)}`, region);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#                    if (config.rds_encryption_kms_alias) {
#                        if (aliasId == kmsKey) {
#                            if (desiredEncryptionLevel <= currentEncryptionLevel) {
#                                helpers.addResult(results, 0,
#                                    `Encryption at rest is enabled via expected KMS key: ${(kmsKey || 'Unknown')} at level ${currentEncryptionLevelString} which is ` +
#                                    `greater than or equal to the desired level ${config.desiredEncryptionLevelString}`,
#                                    region, dbResource, custom);
#                            } else {
#                                helpers.addResult(results, 2,
#                                    `Encryption at rest is enabled via expected KMS key: ${(kmsKey || 'Unknown')} at level ${currentEncryptionLevelString} which is ` +
#                                    `less than the desired level ${config.desiredEncryptionLevelString}`,
#                                    region, dbResource, custom);
#                            }
#                        } else {
#                            helpers.addResult(results, 2,
#                                `Encryption at rest is enabled, but is not using expected KMS key: ${aliasId}. Using key: ${(kmsKey || 'Unknown')}`,
#                                region, dbResource, custom);
#                        }
#                    } else {
#                        if (desiredEncryptionLevel <= currentEncryptionLevel) {
#                            helpers.addResult(results, 0,
#                                `Encryption at rest is enabled via KMS key: ${(kmsKey || 'Unknown')} at level ${currentEncryptionLevelString} which is ` +
#                                `greater than or equal to the desired level ${config.desiredEncryptionLevelString}`,
#                                region, dbResource);
#                        } else {
#                            helpers.addResult(results, 2,
#                                `Encryption at rest is enabled via KMS key: ${(kmsKey || 'Unknown')} at level ${currentEncryptionLevelString} which is ` +
#                                `less than the desired level ${config.desiredEncryptionLevelString}`,
#                                region, dbResource);
#                        }
#                    }
#                } else {
#                    helpers.addResult(results, 2, 'Encryption at rest is not enabled', region, dbResource);
#                }
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
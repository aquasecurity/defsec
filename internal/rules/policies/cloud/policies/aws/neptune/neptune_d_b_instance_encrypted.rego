# METADATA
# title :"Neptune Database Instance Encrypted"
# description: "Ensure that your AWS Neptune database instances are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Neptune
#   severity: LOW
#   short_code: neptune-d-b-instance-encrypted 
#   recommended_action: "Encrypt Neptune database with desired encryption level"
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
#            desiredEncryptionLevelString: settings.neptune_db_desired_encryption_level || this.settings.neptune_db_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.neptune, function(region, rcb){
#            var describeDBClusters = helpers.addSource(cache, source,
#                ['neptune', 'describeDBClusters', region]);
#
#            if (!describeDBClusters) return rcb();
#
#            if (describeDBClusters.err || !describeDBClusters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list Neptune database instances: ${helpers.addError(describeDBClusters)}`, region);
#                return rcb();
#            }
#
#            if (!describeDBClusters.data.length) {
#                helpers.addResult(results, 0,
#                    'No Neptune database instances found', region);
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
#            for (let cluster of describeDBClusters.data) {
#                if (!cluster.DBClusterArn) continue;
#
#                let resource = cluster.DBClusterArn;
#
#                if (cluster.KmsKeyId) {
#                    var kmsKeyId = cluster.KmsKeyId.split('/')[1] ? cluster.KmsKeyId.split('/')[1] : cluster.KmsKeyId;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]); 
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, cluster.KmsKeyId);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `Neptune database instance is encrypted with ${currentEncryptionLevelString} \
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Neptune database instance is encrypted with ${currentEncryptionLevelString} \
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'Neptune database instance does not have encryption enabled',
#                        region, resource);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }
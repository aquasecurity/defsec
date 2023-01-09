# METADATA
# title :"MemoryDB Cluster Encrypted"
# description: "Ensure that your Amazon MemoryDB cluster is encrypted with desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/memorydb/latest/devguide/at-rest-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:MemoryDB
#   severity: LOW
#   short_code: memorydb-cluster-encrypted 
#   recommended_action: "Modify MemoryDB cluster encryption configuration to use desired encryption key"
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
#            desiredEncryptionLevelString: settings.memorydb_cluster_target_encryption_level || this.settings.memorydb_cluster_target_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.memorydb, function(region, rcb){
#            var describeClusters = helpers.addSource(cache, source,
#                ['memorydb', 'describeClusters', region]);
#                
#            if (!describeClusters) return rcb();
#
#            if (describeClusters.err || !describeClusters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list MemoryDB clusters: ${helpers.addError(describeClusters)}`, region);
#                return rcb();
#            }
#
#            if (!describeClusters.data.length) {
#                helpers.addResult(results, 0,
#                    'No MemoryDB clusters found', region);
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
#            for (let cluster of describeClusters.data) {
#                if (!cluster.ARN) continue;
#
#                let resource = cluster.ARN;
#
#                if (!cluster.KmsKeyId) {
#                    currentEncryptionLevel = 2; //awskms
#                } else {
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
#                }
#
#                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                    helpers.addResult(results, 0,
#                        `MemoryDB cluster is encrypted with ${currentEncryptionLevelString} \
#                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `MemoryDB cluster is encrypted with ${currentEncryptionLevelString} \
#                        which is less than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }